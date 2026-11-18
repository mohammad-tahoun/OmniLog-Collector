package buffer

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"forcefields-agent/internal/collectors"
)

// DiskQueue provides persistent zero-loss store-and-forward event buffering.
type DiskQueue struct {
	mu           sync.Mutex
	dir          string
	maxBatchSize int
	statePath    string
	currentFile  *os.File
	currentSeq   uint64
	readSeq      uint64
	depth        int64
}

type queueIndexState struct {
	ReadSeq    uint64 `json:"read_seq"`
	CurrentSeq uint64 `json:"current_seq"`
	Depth      int64  `json:"depth"`
}

type queueEntry struct {
	Seq  uint64                `json:"seq"`
	Item collectors.RawLogItem `json:"item"`
}

// NewDiskQueue initializes or opens an existing persistent disk queue directory.
func NewDiskQueue(dir string, maxBatchSize int) (*DiskQueue, error) {
	if maxBatchSize <= 0 {
		maxBatchSize = 100
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create queue dir: %w", err)
	}

	statePath := filepath.Join(dir, "queue_state.json")
	q := &DiskQueue{
		dir:          dir,
		maxBatchSize: maxBatchSize,
		statePath:    statePath,
	}

	// Load existing index state
	state, err := q.loadState()
	if err == nil {
		q.readSeq = state.ReadSeq
		q.currentSeq = state.CurrentSeq
		q.depth = state.Depth
	} else {
		q.readSeq = 1
		q.currentSeq = 0
		q.depth = 0
		_ = q.saveState()
	}

	// Recount depth from disk if needed
	q.reconcileDepth()

	return q, nil
}

func (q *DiskQueue) loadState() (*queueIndexState, error) {
	data, err := os.ReadFile(q.statePath)
	if err != nil {
		return nil, err
	}
	var state queueIndexState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

func (q *DiskQueue) saveState() error {
	state := queueIndexState{
		ReadSeq:    q.readSeq,
		CurrentSeq: q.currentSeq,
		Depth:      q.depth,
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp := q.statePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, q.statePath)
}

func (q *DiskQueue) reconcileDepth() {
	files, err := filepath.Glob(filepath.Join(q.dir, "segment_*.wal"))
	if err != nil || len(files) == 0 {
		if q.depth < 0 {
			q.depth = 0
		}
		return
	}

	var count int64 = 0
	for _, f := range files {
		file, err := os.Open(f)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			var entry queueEntry
			if err := json.Unmarshal(line, &entry); err == nil {
				if entry.Seq >= q.readSeq {
					count++
				}
			}
		}
		file.Close()
	}
	q.depth = count
	_ = q.saveState()
}

// Enqueue persists a raw event into the local store-and-forward queue.
func (q *DiskQueue) Enqueue(item collectors.RawLogItem) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.currentSeq++
	entry := queueEntry{
		Seq:  q.currentSeq,
		Item: item,
	}

	segmentIndex := (q.currentSeq - 1) / 5000
	segmentName := fmt.Sprintf("segment_%08d.wal", segmentIndex)
	segmentPath := filepath.Join(q.dir, segmentName)

	file, err := os.OpenFile(segmentPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		q.currentSeq--
		return fmt.Errorf("failed to open queue segment: %w", err)
	}
	defer file.Close()

	data, err := json.Marshal(entry)
	if err != nil {
		q.currentSeq--
		return fmt.Errorf("failed to marshal entry: %w", err)
	}

	data = append(data, '\n')
	if _, err := file.Write(data); err != nil {
		q.currentSeq--
		return fmt.Errorf("failed to write to queue file: %w", err)
	}

	_ = file.Sync()
	q.depth++
	_ = q.saveState()

	return nil
}

// PeekBatch retrieves up to `limit` events starting at readSeq without removing them yet.
// It returns the events and the highest sequence number in the batch.
func (q *DiskQueue) PeekBatch(limit int) ([]collectors.RawLogItem, uint64, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if limit <= 0 {
		limit = q.maxBatchSize
	}

	files, err := filepath.Glob(filepath.Join(q.dir, "segment_*.wal"))
	if err != nil || len(files) == 0 {
		return nil, 0, nil
	}
	sort.Strings(files)

	var items []collectors.RawLogItem
	var maxSeqInBatch uint64 = 0

	for _, f := range files {
		if len(items) >= limit {
			break
		}

		file, err := os.Open(f)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(file)
		// Support larger event lines if required
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 10*1024*1024)

		for scanner.Scan() {
			if len(items) >= limit {
				break
			}

			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}

			var entry queueEntry
			if err := json.Unmarshal(line, &entry); err != nil {
				continue
			}

			if entry.Seq >= q.readSeq {
				items = append(items, entry.Item)
				if entry.Seq > maxSeqInBatch {
					maxSeqInBatch = entry.Seq
				}
			}
		}
		file.Close()
	}

	return items, maxSeqInBatch, nil
}

// AckBatch marks events up to `highestSeq` as safely sent and cleans up consumed segment files.
func (q *DiskQueue) AckBatch(highestSeq uint64) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if highestSeq < q.readSeq {
		return nil
	}

	delta := int64(highestSeq - q.readSeq + 1)
	q.readSeq = highestSeq + 1
	q.depth -= delta
	if q.depth < 0 {
		q.depth = 0
	}
	_ = q.saveState()

	// Clean up fully consumed segments
	currentActiveSeg := (q.currentSeq - 1) / 5000
	readSeg := (q.readSeq - 1) / 5000

	files, err := filepath.Glob(filepath.Join(q.dir, "segment_*.wal"))
	if err == nil {
		for _, f := range files {
			base := filepath.Base(f)
			base = strings.TrimPrefix(base, "segment_")
			base = strings.TrimSuffix(base, ".wal")
			idx, err := strconv.ParseUint(base, 10, 64)
			if err == nil && idx < readSeg && idx < currentActiveSeg {
				_ = os.Remove(f)
			}
		}
	}

	return nil
}

// Depth returns the current count of events stored in the queue.
func (q *DiskQueue) Depth() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.depth
}

// Close closes any open file handles.
func (q *DiskQueue) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.currentFile != nil {
		_ = q.currentFile.Close()
		q.currentFile = nil
	}
	return nil
}
