package sshclient

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh"
)

type hostKeyEntry struct {
	Type string `json:"type"`
	Key  string `json:"key"`
}

type hostKeyStore struct {
	mu      sync.Mutex
	path    string
	entries map[string]hostKeyEntry
}

func loadHostKeyStore(path string) *hostKeyStore {
	s := &hostKeyStore{path: path, entries: map[string]hostKeyEntry{}}
	raw, err := os.ReadFile(path)
	if err == nil {
		_ = json.Unmarshal(raw, &s.entries)
	}
	if s.entries == nil {
		s.entries = map[string]hostKeyEntry{}
	}
	return s
}

func (s *hostKeyStore) save() error {
	if dir := filepath.Dir(s.path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	raw, err := json.MarshalIndent(s.entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, append(raw, '\n'), 0o600)
}

// TrustedHostKeyCallback returns an ssh.HostKeyCallback implementing
// trust-on-first-use pinning: the first key seen for an address is stored
// at path and trusted silently. A later connection to the same address
// presenting a different key is rejected outright — that means either the
// device was reinstalled/rekeyed or the connection is being intercepted,
// and either way it needs a human to confirm before this hands over the
// admin password again. Ported from NSELocalSSH's internal/nse/hostkeys.go.
func TrustedHostKeyCallback(path string) ssh.HostKeyCallback {
	store := loadHostKeyStore(path)
	return func(addr string, _ net.Addr, key ssh.PublicKey) error {
		store.mu.Lock()
		defer store.mu.Unlock()

		encoded := base64.StdEncoding.EncodeToString(key.Marshal())
		existing, ok := store.entries[addr]
		if !ok {
			store.entries[addr] = hostKeyEntry{Type: key.Type(), Key: encoded}
			if err := store.save(); err != nil {
				return fmt.Errorf("could not save trusted host key for %s: %w", addr, err)
			}
			return nil
		}
		if existing.Type == key.Type() && existing.Key == encoded {
			return nil
		}
		return fmt.Errorf(
			"refusing to connect: the SSH host key for %s does not match the one trusted on first connect "+
				"(now presenting %s fingerprint %s). This means the device was reinstalled/replaced, or the "+
				"connection is being intercepted. If you're sure the device changed legitimately, remove the "+
				"%q entry from %s and reconnect",
			addr, key.Type(), ssh.FingerprintSHA256(key), addr, path,
		)
	}
}
