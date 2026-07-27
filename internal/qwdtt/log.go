package qwdtt

import (
	"fmt"
	"sync"
	"time"
)

type LogEntry struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
}
type LogBook struct {
	mu      sync.RWMutex
	entries []LogEntry
	limit   int
}

func NewLogBook() *LogBook { return &LogBook{limit: 1500} }
func (l *LogBook) Add(level, format string, args ...interface{}) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, LogEntry{Time: time.Now(), Level: level, Message: fmt.Sprintf(format, args...)})
	if len(l.entries) > l.limit {
		l.entries = l.entries[len(l.entries)-l.limit:]
	}
}
func (l *LogBook) Snapshot() []LogEntry {
	if l == nil {
		return nil
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return append([]LogEntry(nil), l.entries...)
}

func (l *LogBook) Clear() {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.entries = nil
	l.mu.Unlock()
}
