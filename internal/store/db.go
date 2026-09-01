// Package store is the SQLite persistence layer. It opens two handles
// against one database file — a single-connection write handle (so the
// poller's mutations serialize without a hand-rolled mutex) and a
// multi-connection read handle for the web dashboard — which is the
// standard way to avoid SQLITE_BUSY under Go's database/sql pooling
// without giving up read concurrency. WAL mode lets those overlap safely.
package store

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

type Store struct {
	writeDB *sql.DB
	readDB  *sql.DB
	Path    string
}

// Open opens (creating if needed) the database file at dataDir/conntrack.db
// and applies any pending migrations.
func Open(dataDir string) (*Store, error) {
	path := filepath.Join(dataDir, "conntrack.db")
	dsn := fmt.Sprintf(
		"file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)",
		path,
	)

	writeDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening write handle: %w", err)
	}
	writeDB.SetMaxOpenConns(1)

	readDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		writeDB.Close()
		return nil, fmt.Errorf("opening read handle: %w", err)
	}
	readDB.SetMaxOpenConns(4)

	s := &Store{writeDB: writeDB, readDB: readDB, Path: path}
	if err := s.migrate(); err != nil {
		writeDB.Close()
		readDB.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	err1 := s.writeDB.Close()
	err2 := s.readDB.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

func (s *Store) migrate() error {
	if _, err := s.writeDB.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		applied_at INTEGER NOT NULL
	)`); err != nil {
		return fmt.Errorf("creating schema_migrations: %w", err)
	}

	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("reading embedded migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		version, err := versionFromFilename(name)
		if err != nil {
			return fmt.Errorf("migration %s: %w", name, err)
		}
		var applied int
		if err := s.writeDB.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, version).Scan(&applied); err != nil {
			return fmt.Errorf("checking migration %d: %w", version, err)
		}
		if applied > 0 {
			continue
		}
		sqlBytes, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("reading migration %s: %w", name, err)
		}
		tx, err := s.writeDB.Begin()
		if err != nil {
			return fmt.Errorf("beginning migration tx: %w", err)
		}
		if _, err := tx.Exec(string(sqlBytes)); err != nil {
			tx.Rollback()
			return fmt.Errorf("applying migration %s: %w", name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`, version, time.Now().Unix()); err != nil {
			tx.Rollback()
			return fmt.Errorf("recording migration %d: %w", version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("committing migration %s: %w", name, err)
		}
	}
	return nil
}

func versionFromFilename(name string) (int, error) {
	i := strings.IndexByte(name, '_')
	if i <= 0 {
		return 0, fmt.Errorf("expected NNNN_name.sql, got %q", name)
	}
	return strconv.Atoi(name[:i])
}

func unixOrNil(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.Unix()
}

func timePtrFromUnix(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := time.Unix(v.Int64, 0).UTC()
	return &t
}
