package forwarder

// queue.go — a durable FIFO backed by newline-delimited JSON segment files.
// Uses ONLY the Go standard library — zero external dependencies.
//
// Layout on disk:
//   <dir>/
//     segments/
//       0000000001.jsonl   <- oldest segment
//       0000000002.jsonl
//
// Each .jsonl file holds up to segmentSize events (one JSON object per line).
// Pop reads from the oldest segment; Push writes to the newest.
// Completed segments are deleted after all events are consumed.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"opensiem/agent/pkg/schema"
)

const (
	segmentSize = 500 // max events per segment file
	maxSegments = 200 // max segments before evicting oldest (~100k events)
)

// Queue is a persistent file-backed FIFO of schema.Events.
type Queue struct {
	dir        string
	mu         sync.Mutex
	logger     *slog.Logger
	writeFile  *os.File
	writeSeq   int64
	writeCount int
}

// NewQueue opens (or creates) the queue directory at dir.
// maxRows is accepted for API compatibility; enforced via maxSegments.
func NewQueue(dir string, _ int, logger *slog.Logger) (*Queue, error) {
	segDir := filepath.Join(dir, "segments")
	if err := os.MkdirAll(segDir, 0755); err != nil {
		return nil, fmt.Errorf("queue: mkdir %q: %w", segDir, err)
	}

	q := &Queue{dir: dir, logger: logger}

	seqs, err := q.listSegments()
	if err != nil {
		return nil, err
	}
	if len(seqs) > 0 {
		q.writeSeq = seqs[len(seqs)-1]
		q.writeCount, _ = countLines(q.segPath(q.writeSeq))
	} else {
		q.writeSeq = 1
	}
	return q, nil
}

// Push appends events to the queue.
func (q *Queue) Push(events []schema.Event) error {
	if len(events) == 0 {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()

	q.evictIfNeeded()

	for _, ev := range events {
		if q.writeCount >= segmentSize {
			if q.writeFile != nil {
				q.writeFile.Close()
				q.writeFile = nil
			}
			q.writeSeq++
			q.writeCount = 0
		}

		if q.writeFile == nil {
			f, err := os.OpenFile(q.segPath(q.writeSeq), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
			if err != nil {
				return fmt.Errorf("queue: open segment: %w", err)
			}
			q.writeFile = f
		}

		b, err := json.Marshal(ev)
		if err != nil {
			q.logger.Warn("queue: marshal failed, skipping", "err", err)
			continue
		}
		if _, err := fmt.Fprintf(q.writeFile, "%s\n", b); err != nil {
			return fmt.Errorf("queue: write: %w", err)
		}
		q.writeCount++
	}
	return nil
}

// Pop removes and returns up to n events from the front of the queue.
func (q *Queue) Pop(n int) ([]schema.Event, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	seqs, err := q.listSegments()
	if err != nil || len(seqs) == 0 {
		return nil, err
	}

	var events []schema.Event
	remaining := n

	for _, seq := range seqs {
		if remaining <= 0 {
			break
		}
		// Don't read from the active write segment unless it's the only one.
		if seq == q.writeSeq && len(seqs) > 1 {
			continue
		}

		path := q.segPath(seq)
		lines, err := readLines(path)
		if err != nil {
			q.logger.Warn("queue: read segment failed", "path", path, "err", err)
			continue
		}

		var keep []string
		for _, line := range lines {
			if remaining <= 0 {
				keep = append(keep, line)
				continue
			}
			var ev schema.Event
			if err := json.Unmarshal([]byte(line), &ev); err != nil {
				q.logger.Warn("queue: unmarshal failed, dropping line", "err", err)
				continue
			}
			events = append(events, ev)
			remaining--
		}

		if len(keep) == 0 {
			if seq == q.writeSeq {
				if q.writeFile != nil {
					q.writeFile.Close()
					q.writeFile = nil
				}
				q.writeCount = 0
			}
			os.Remove(path)
		} else {
			// On Windows, renaming over an open file handle is not permitted.
			// Close the write handle before rewriting, then reopen after.
			isWriteSeg := seq == q.writeSeq
			if isWriteSeg && q.writeFile != nil {
				q.writeFile.Close()
				q.writeFile = nil
			}
			if err := writeLines(path, keep); err != nil {
				q.logger.Warn("queue: rewrite segment failed", "err", err)
			} else if isWriteSeg {
				// Reopen so Push() can continue appending.
				f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
				if err != nil {
					q.logger.Warn("queue: reopen write segment failed", "err", err)
				} else {
					q.writeFile = f
					q.writeCount = len(keep)
				}
			}
			break
		}
	}

	return events, nil
}

// Len returns the approximate number of events currently queued.
func (q *Queue) Len() (int64, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	seqs, err := q.listSegments()
	if err != nil {
		return 0, err
	}
	var total int64
	for _, seq := range seqs {
		n, _ := countLines(q.segPath(seq))
		total += int64(n)
	}
	return total, nil
}

// Close flushes and closes any open file handles.
func (q *Queue) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.writeFile != nil {
		err := q.writeFile.Close()
		q.writeFile = nil
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (q *Queue) segPath(seq int64) string {
	return filepath.Join(q.dir, "segments", fmt.Sprintf("%010d.jsonl", seq))
}

func (q *Queue) listSegments() ([]int64, error) {
	entries, err := os.ReadDir(filepath.Join(q.dir, "segments"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("queue: readdir: %w", err)
	}
	var seqs []int64
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		seq, err := strconv.ParseInt(strings.TrimSuffix(e.Name(), ".jsonl"), 10, 64)
		if err != nil {
			continue
		}
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	return seqs, nil
}

func (q *Queue) evictIfNeeded() {
	seqs, err := q.listSegments()
	if err != nil || len(seqs) <= maxSegments {
		return
	}
	for i := 0; i < len(seqs)-maxSegments; i++ {
		os.Remove(q.segPath(seqs[i]))
		q.logger.Warn("queue: evicted oldest segment (queue full)", "seq", seqs[i])
	}
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			lines = append(lines, line)
		}
	}
	return lines, sc.Err()
}

func writeLines(path string, lines []string) error {
	f, err := os.CreateTemp(filepath.Dir(path), "seg-*.tmp")
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}
	f.Close()
	return os.Rename(f.Name(), path)
}

func countLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			n++
		}
	}
	return n, sc.Err()
}
