// wrapper.go
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

// var EncryptedConfig = []byte{...}  // 由 encrypt.go 生成的 config_blob.go 提供

// ------------------- KDF / AES-GCM -------------------
func deriveKey(password []byte, salt []byte) []byte {
	timeParam := uint32(1)
	memory := uint32(64 * 1024) // 64MB
	threads := uint8(4)
	keyLen := uint32(32)
	return argon2.IDKey(password, salt, timeParam, memory, threads, keyLen)
}

func decrypt(blob []byte, password []byte) ([]byte, error) {
	if len(blob) < 16+12 {
		return nil, errors.New("blob too short")
	}
	salt := blob[:16]
	nonce := blob[16 : 16+12]
	ct := blob[16+12:]

	key := deriveKey(password, salt)
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesgcm.Open(nil, nonce, ct, nil)
}

func promptPassword(prompt string) ([]byte, error) {
	fmt.Print(prompt)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	return pw, err
}

func zeroize(b []byte) {
	if b != nil {
		for i := range b {
			b[i] = 0
		}
	}
}

// ------------------- 公网 IP 日志脱敏 -------------------
var (
	ipv4Re = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Re = regexp.MustCompile(`\b([0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b`)
	// 新增：IPv4-mapped IPv6 形如 ::ffff:1.2.3.4
	ipv6MappedV4Re = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{0,4}:){2,6}ffff:(?:\d{1,3}\.){3}\d{1,3}\b`)
)

var reservedNets []*net.IPNet

func init() {
	cidrs := []string{
		// IPv4 私有/保留
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
		"192.0.0.0/24", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
		"224.0.0.0/4",
		// IPv6 非公网
		"::1/128", "fc00::/7", "fe80::/10", "::/128",
	}
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err == nil {
			reservedNets = append(reservedNets, n)
		}
	}
}

func isReservedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	for _, n := range reservedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// 统一把任意 IP（IPv4/IPv6/IPv4-mapped IPv6）替换为 "*"
func sanitizeLine(line string) string {
	out := ipv6MappedV4Re.ReplaceAllString(line, "*")
	out = ipv4Re.ReplaceAllString(out, "*")
	out = ipv6Re.ReplaceAllString(out, "*")
	return out
}

func streamAndSanitize(r io.ReadCloser, w io.Writer, done chan<- struct{}) {
	defer func() {
		r.Close()
		if done != nil {
			done <- struct{}{}
		}
	}()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		fmt.Fprintln(w, sanitizeLine(sc.Text()))
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintf(w, "[log-sanitizer] stream error: %v\n", err)
	}
}

// ------------------- OpenVPN 启动（stdin / 临时文件） -------------------
func configArgForStdin() string {
	// Linux / macOS 更通用：/dev/stdin
	switch runtime.GOOS {
	case "linux", "darwin", "freebsd", "openbsd", "netbsd":
		return "/dev/stdin"
	default:
		return "-" // 其他平台兜底
	}
}

func startOpenVPNWithStdin(ctx context.Context, plain []byte, args []string, cfgArg string) (*exec.Cmd, error) {
	cmdArgs := append([]string{"--config", cfgArg}, args...)
	cmd := exec.CommandContext(ctx, "openvpn", cmdArgs...)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		stdin.Close()
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		stdin.Close()
		return nil, err
	}

	done := make(chan struct{}, 2)
	go streamAndSanitize(stdout, os.Stdout, done)
	go streamAndSanitize(stderr, os.Stderr, done)

	// 同步写入配置，确保交付完成再返回（配置一般很小，不会阻塞太久）
	if _, err := io.Copy(stdin, bytes.NewReader(plain)); err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("write stdin: %w", err)
	}
	_ = stdin.Close()
	return cmd, nil
}

func startOpenVPNWithTempFile(ctx context.Context, plain []byte, args []string) (*exec.Cmd, error) {
	tmp, err := os.CreateTemp("", "ovpn-*.conf")
	if err != nil {
		return nil, err
	}
	path := tmp.Name()
	_ = tmp.Chmod(0600)
	if _, err := tmp.Write(plain); err != nil {
		tmp.Close()
		os.Remove(path)
		return nil, err
	}
	tmp.Sync()
	tmp.Close()

	cmdArgs := append([]string{"--config", path}, args...)
	cmd := exec.CommandContext(ctx, "openvpn", cmdArgs...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		os.Remove(path)
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		os.Remove(path)
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		os.Remove(path)
		return nil, err
	}
	_ = os.Remove(path) // 立即 unlink

	done := make(chan struct{}, 2)
	go streamAndSanitize(stdout, os.Stdout, done)
	go streamAndSanitize(stderr, os.Stderr, done)
	return cmd, nil
}

func forwardSignals(proc *os.Process, cancel context.CancelFunc) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range ch {
			if proc != nil {
				_ = proc.Signal(sig)
			}
			if sig == syscall.SIGINT || sig == syscall.SIGTERM {
				if cancel != nil {
					cancel()
				}
			}
		}
	}()
}

// ------------------- main -------------------
func main() {
	openvpnArgs := os.Args[1:]

	// 读取口令并解密
	var plain []byte
	var err error
	for i := 0; i < 3; i++ {
		pw, e := promptPassword("Enter passphrase to decrypt config: ")
		if e != nil {
			fmt.Fprintln(os.Stderr, "read password error:", e)
			os.Exit(2)
		}
		plain, err = decrypt(EncryptedConfig, pw)
		zeroize(pw)
		if err == nil {
			break
		}
		fmt.Fprintln(os.Stderr, "decrypt failed:", err)
		if i < 2 {
			fmt.Println("Try again.")
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to decrypt config after attempts:", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// --- 尝试 stdin（优先 /dev/stdin），快速失败自动回退 ---
	cfgArg := configArgForStdin()
	cmd, err := startOpenVPNWithStdin(ctx, plain, openvpnArgs, cfgArg)
	if err == nil {
		// 配置已写入 stdin，可以清零
		zeroize(plain)

		// 1.5s 快速失败判断：若很快非零退出，多半是不支持 stdin，自动回退到临时文件
		waitCh := make(chan error, 1)
		go func() { waitCh <- cmd.Wait() }()
		select {
		case werr := <-waitCh:
			// 进程很快退出
			if werr != nil {
				fmt.Fprintln(os.Stderr, "stdin mode appears unsupported; falling back to temp file method.")
				// 尝试改用 "-" 再试一次（有些平台只认 "-"）
				if cfgArg != "-" {
					cmd2, err2 := startOpenVPNWithStdin(ctx, plain, openvpnArgs, "-")
					if err2 == nil {
						// 重新 wait，给一个 1.5s 快速失败窗口
						waitCh2 := make(chan error, 1)
						go func() { waitCh2 <- cmd2.Wait() }()
						select {
						case w2 := <-waitCh2:
							if w2 != nil {
								// 仍然不行，彻底回退到临时文件
								goto FALLBACK_FILE
							}
							// 正常运行
							forwardSignals(cmd2.Process, cancel)
							if err := <-waitCh2; err != nil {
								fmt.Fprintln(os.Stderr, "openvpn exited with error:", err)
								os.Exit(1)
							}
							os.Exit(0)
						case <-time.After(1500 * time.Millisecond):
							// 认为已正常启动，等待最终结束
							forwardSignals(cmd2.Process, cancel)
							if err := <-waitCh2; err != nil {
								fmt.Fprintln(os.Stderr, "openvpn exited with error:", err)
								os.Exit(1)
							}
							os.Exit(0)
						}
					}
				}
				// 直接回退到临时文件
				goto FALLBACK_FILE
			}
			// werr == nil 且快速退出（极少见），当作正常结束
			os.Exit(0)
		case <-time.After(1500 * time.Millisecond):
			// 认为已正常启动，进入正常等待
			forwardSignals(cmd.Process, cancel)
			if err := <-waitCh; err != nil {
				fmt.Fprintln(os.Stderr, "openvpn exited with error:", err)
				os.Exit(1)
			}
			os.Exit(0)
		}
	} else {
		// stdin 直接启动失败，回退
		fmt.Fprintln(os.Stderr, "stdin method failed to start, falling back to temp file method.")
	}

FALLBACK_FILE:
	// --- 临时文件方案 ---
	cmdFile, err := startOpenVPNWithTempFile(ctx, plain, openvpnArgs)
	zeroize(plain)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to start openvpn (temp file):", err)
		os.Exit(1)
	}
	// 不打印 tmp 路径，只打印 PID（日志仍会脱敏公网 IP）
	fmt.Fprintf(os.Stderr, "Started openvpn. PID=%d\n", cmdFile.Process.Pid)
	forwardSignals(cmdFile.Process, cancel)
	if err := cmdFile.Wait(); err != nil {
		fmt.Fprintln(os.Stderr, "openvpn exited with error:", err)
		os.Exit(1)
	}
}
