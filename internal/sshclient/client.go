// Package sshclient is a read-only SSH client for Cambium NSE3000/4000
// firewalls, ported from the persistent-PTY-session approach in
// SiCambium/NSELocalSSH's internal/nse/client.go. Only the subset needed to
// run "show ..." commands is kept here — no config-write / RunSequence /
// sub-context unwind logic, since this tool never writes to the device.
package sshclient

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"regexp"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var promptBytes = regexp.MustCompile(`[A-Za-z0-9._-]+\([^)]*\)#\s*$`)

// Config holds one firewall's SSH connection details.
type Config struct {
	Host     string
	Port     int
	User     string
	Password string
}

func (c Config) Addr() string {
	port := c.Port
	if port == 0 {
		port = 22
	}
	return net.JoinHostPort(c.Host, fmt.Sprintf("%d", port))
}

// Client is a persistent SSH session against one device. It reconnects
// automatically on failure. Safe for concurrent use — all methods take an
// internal lock, matching the upstream client's approach of holding the
// lock for the duration of a whole command (not just the write), since the
// risk being defended against is a concurrent poll interleaving with
// another poll's command/response on the same shared shell.
type Client struct {
	cfg             Config
	hostKeyCallback ssh.HostKeyCallback

	mu       sync.Mutex
	conn     *ssh.Client
	session  *ssh.Session
	stdin    io.WriteCloser
	incoming <-chan []byte
}

func New(cfg Config, hostKeyCallback ssh.HostKeyCallback) *Client {
	return &Client{cfg: cfg, hostKeyCallback: hostKeyCallback}
}

func (c *Client) connect() error {
	c.closeLocked()
	config := &ssh.ClientConfig{
		User:            c.cfg.User,
		Auth:            []ssh.AuthMethod{ssh.Password(c.cfg.Password)},
		HostKeyCallback: c.hostKeyCallback,
		Timeout:         12 * time.Second,
	}
	conn, err := ssh.Dial("tcp", c.cfg.Addr(), config)
	if err != nil {
		return err
	}
	session, err := conn.NewSession()
	if err != nil {
		conn.Close()
		return err
	}
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm", 50, 200, modes); err != nil {
		session.Close()
		conn.Close()
		return err
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		conn.Close()
		return err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		conn.Close()
		return err
	}
	if err := session.Shell(); err != nil {
		session.Close()
		conn.Close()
		return err
	}
	ch := make(chan []byte, 32)
	go func() {
		buf := make([]byte, 8192)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				b := make([]byte, n)
				copy(b, buf[:n])
				ch <- b
			}
			if err != nil {
				close(ch)
				return
			}
		}
	}()
	c.conn = conn
	c.session = session
	c.stdin = stdin
	c.incoming = ch
	if _, err := c.waitPrompt(15 * time.Second); err != nil {
		c.closeLocked()
		return err
	}
	return nil
}

func (c *Client) waitPrompt(timeout time.Duration) (string, error) {
	deadline := time.After(timeout)
	var acc bytes.Buffer
	for {
		select {
		case <-deadline:
			tail := acc.String()
			if len(tail) > 200 {
				tail = tail[len(tail)-200:]
			}
			return acc.String(), fmt.Errorf("timed out waiting for NSE prompt: %s", tail)
		case chunk, ok := <-c.incoming:
			if !ok {
				return acc.String(), fmt.Errorf("ssh session closed")
			}
			acc.Write(chunk)
			b := acc.Bytes()
			tail := b[max(0, len(b)-80):]
			if bytes.Contains(tail, []byte("--More--")) || bytes.Contains(tail, []byte("--more--")) {
				_, _ = c.stdin.Write([]byte(" "))
			}
			if promptBytes.Find(b) != nil {
				return acc.String(), nil
			}
		}
	}
}

func (c *Client) ensure() error {
	if c.conn != nil && c.session != nil && c.incoming != nil {
		return nil
	}
	return c.connect()
}

// Run sends one command line and returns the raw response (echoed command
// line + output + trailing prompt included — callers strip that via
// nse.ParseConntrackFlows / ParseConntrackSummary, which know the exact
// command string to strip).
func (c *Client) Run(command string, timeout time.Duration) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensure(); err != nil {
		return "", err
	}
	if _, err := c.stdin.Write([]byte(command + "\r")); err != nil {
		if err2 := c.connect(); err2 != nil {
			return "", err
		}
		if _, err = c.stdin.Write([]byte(command + "\r")); err != nil {
			return "", err
		}
	}
	out, err := c.waitPrompt(timeout)
	if err != nil {
		c.closeLocked()
		return out, err
	}
	return out, nil
}

func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLocked()
}

func (c *Client) closeLocked() {
	if c.session != nil {
		_ = c.session.Close()
	}
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.session = nil
	c.conn = nil
	c.stdin = nil
	c.incoming = nil
}
