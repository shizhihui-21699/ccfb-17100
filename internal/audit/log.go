// Package audit is an append-only, hash-chained event log.
//
// "Trace back who created it" is only meaningful if the trail can't be edited
// after the fact. Each entry carries the hash of its predecessor, so removing
// or altering an entry breaks the chain for everything after it. Verification
// is cheap enough to run on every read of the abuse report.
//
// This is tamper-*evident*, not tamper-proof: someone with write access to the
// file can rewrite the whole chain. Production deployments ship entries to a
// separate append-only sink (WORM storage / SIEM) as they are written; the
// chain then makes local edits detectable against the sink.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type Event struct {
	Seq       int64             `json:"seq"`
	At        time.Time         `json:"at"`
	Action    string            `json:"action"`
	Actor     string            `json:"actor"`
	ActorDept string            `json:"actor_dept,omitempty"`
	LinkID    string            `json:"link_id,omitempty"`
	Code      string            `json:"code,omitempty"`
	Target    string            `json:"target,omitempty"`
	Meta      map[string]string `json:"meta,omitempty"`
	PrevHash  string            `json:"prev_hash"`
	Hash      string            `json:"hash"`
}

const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Log is a chain of events. The zero value is not usable; call Open or New.
type Log struct {
	mu      sync.Mutex
	entries []Event
	prev    string
	f       *os.File // optional durable sink
	nowFn   func() time.Time
}

func New() *Log {
	return &Log{prev: genesisHash, nowFn: time.Now}
}

// Open appends to (or creates) a newline-delimited JSON file, replaying
// existing entries to recover the chain head.
func Open(path string) (*Log, error) {
	l := &Log{prev: genesisHash, nowFn: time.Now}
	if data, err := os.ReadFile(path); err == nil {
		for _, line := range splitLines(data) {
			if len(line) == 0 {
				continue
			}
			var e Event
			if err := json.Unmarshal(line, &e); err != nil {
				return nil, fmt.Errorf("audit: replay %s: %w", path, err)
			}
			l.entries = append(l.entries, e)
			l.prev = e.Hash
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	l.f = f
	return l, nil
}

func (l *Log) Close() error {
	if l.f != nil {
		return l.f.Close()
	}
	return nil
}

// Append records one event, computing its hash over the previous hash plus a
// canonical encoding of the payload.
func (l *Log) Append(e Event) (Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.Seq = int64(len(l.entries)) + 1
	if e.At.IsZero() {
		e.At = l.nowFn()
	}
	e.PrevHash = l.prev
	h, err := hashEvent(e)
	if err != nil {
		return Event{}, err
	}
	e.Hash = h
	l.entries = append(l.entries, e)
	l.prev = h
	if l.f != nil {
		b, err := json.Marshal(e)
		if err != nil {
			return Event{}, err
		}
		if _, err := l.f.Write(append(b, '\n')); err != nil {
			return Event{}, err
		}
	}
	return e, nil
}

// Verify replays the chain and reports the first break, if any.
func (l *Log) Verify() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return verify(l.entries)
}

func verify(entries []Event) error {
	prev := genesisHash
	for i, e := range entries {
		if e.Seq != int64(i)+1 {
			return fmt.Errorf("audit: entry %d has seq %d", i, e.Seq)
		}
		if e.PrevHash != prev {
			return fmt.Errorf("audit: entry %d prev_hash mismatch", i)
		}
		want, err := hashEvent(e)
		if err != nil {
			return err
		}
		if want != e.Hash {
			return fmt.Errorf("audit: entry %d hash mismatch", i)
		}
		prev = e.Hash
	}
	return nil
}

// Entries returns a copy of the chain (optionally filtered by link id).
func (l *Log) Entries() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Event, len(l.entries))
	copy(out, l.entries)
	return out
}

func (l *Log) ForLink(linkID string) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Event
	for _, e := range l.entries {
		if e.LinkID == linkID {
			out = append(out, e)
		}
	}
	return out
}

// hashEvent canonicalizes the payload deterministically. Meta is a map, so it
// is re-marshalled by encoding/json, which sorts keys — deterministic.
func hashEvent(e Event) (string, error) {
	payload := struct {
		Seq       int64             `json:"seq"`
		At        int64             `json:"at"` // unix nanos: avoids TZ/monotonic noise
		Action    string            `json:"action"`
		Actor     string            `json:"actor"`
		ActorDept string            `json:"actor_dept,omitempty"`
		LinkID    string            `json:"link_id,omitempty"`
		Code      string            `json:"code,omitempty"`
		Target    string            `json:"target,omitempty"`
		Meta      map[string]string `json:"meta,omitempty"`
		PrevHash  string            `json:"prev_hash"`
	}{
		Seq: e.Seq, At: e.At.UTC().UnixNano(), Action: e.Action,
		Actor: e.Actor, ActorDept: e.ActorDept, LinkID: e.LinkID,
		Code: e.Code, Target: e.Target, Meta: e.Meta, PrevHash: e.PrevHash,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(e.PrevHash), b...))
	return hex.EncodeToString(sum[:]), nil
}

func splitLines(data []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range data {
		if c == '\n' {
			out = append(out, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		out = append(out, data[start:])
	}
	return out
}
