//go:build linux

package collectors

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	reAuditMsgID = regexp.MustCompile(`msg=audit\((\d+\.\d+):(\d+)\):?`)
	reAuditKV    = regexp.MustCompile(`([a-zA-Z0-9_]+)=(?:"([^"]*)"|(\S+))`)
)

type auditRecordGroup struct {
	Timestamp float64
	Serial    string
	Records   map[string]map[string]string
	RawLines  []string
	LastSeen  time.Time
}

// LinuxAuditdCollector reads /var/log/audit/audit.log in real time, groups multi-line events,
// decodes hex arguments, and enriches live process metadata via /proc.
type LinuxAuditdCollector struct {
	mu         sync.Mutex
	path       string
	offset     int64
	inode      uint64
	stateFile  string
	groups     map[string]*auditRecordGroup
	stopCh     chan struct{}
	cancelFunc context.CancelFunc
}

// NewLinuxAuditdCollector creates an auditd log collector.
func NewLinuxAuditdCollector(auditLogPath, stateFile string) *LinuxAuditdCollector {
	if auditLogPath == "" {
		auditLogPath = "/var/log/audit/audit.log"
	}
	if stateFile == "" {
		stateFile = "./data/auditd_offset.json"
	}
	return &LinuxAuditdCollector{
		path:      auditLogPath,
		stateFile: stateFile,
		groups:    make(map[string]*auditRecordGroup),
		stopCh:    make(chan struct{}),
	}
}

func (c *LinuxAuditdCollector) Name() string {
	return "linux_auditd_collector"
}

func (c *LinuxAuditdCollector) Start(ctx context.Context, out chan<- RawLogItem) error {
	ctx, cancel := context.WithCancel(ctx)
	c.cancelFunc = cancel

	// Flusher for completed grouped audit events
	go c.flushWorker(ctx, out)
	// File tailer
	go c.tailLoop(ctx, out)

	return nil
}

func (c *LinuxAuditdCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancelFunc != nil {
		c.cancelFunc()
	}
	select {
	case <-c.stopCh:
	default:
		close(c.stopCh)
	}
	return nil
}

func (c *LinuxAuditdCollector) flushWorker(ctx context.Context, out chan<- RawLogItem) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.flushOldGroups(out, 300*time.Millisecond)
		}
	}
}

func (c *LinuxAuditdCollector) flushOldGroups(out chan<- RawLogItem, maxAge time.Duration) {
	c.mu.Lock()
	now := time.Now()
	var toDelete []string

	for key, group := range c.groups {
		if now.Sub(group.LastSeen) > maxAge {
			item := c.compileGroupToRawItem(group)
			select {
			case out <- item:
			default:
			}
			toDelete = append(toDelete, key)
		}
	}

	for _, k := range toDelete {
		delete(c.groups, k)
	}
	c.mu.Unlock()
}

func (c *LinuxAuditdCollector) tailLoop(ctx context.Context, out chan<- RawLogItem) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.readAvailable(out)
		}
	}
}

func (c *LinuxAuditdCollector) readAvailable(out chan<- RawLogItem) {
	fileInfo, err := os.Stat(c.path)
	if err != nil {
		return
	}

	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}

	currentInode := stat.Ino
	currentSize := fileInfo.Size()

	if c.inode != currentInode || c.offset > currentSize {
		c.inode = currentInode
		if currentSize > 32768 {
			c.offset = currentSize - 32768
		} else {
			c.offset = 0
		}
	}

	if currentSize <= c.offset {
		return
	}

	file, err := os.Open(c.path)
	if err != nil {
		return
	}
	defer file.Close()

	if _, err := file.Seek(c.offset, io.SeekStart); err != nil {
		return
	}

	scanner := bufio.NewScanner(file)
	newOffset := c.offset

	for scanner.Scan() {
		line := scanner.Text()
		newOffset += int64(len(scanner.Bytes())) + 1
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		c.processAuditLine(line, out)
	}

	c.offset = newOffset
}

func (c *LinuxAuditdCollector) processAuditLine(line string, out chan<- RawLogItem) {
	m := reAuditMsgID.FindStringSubmatch(line)
	if len(m) < 3 {
		return
	}

	tsFloat, _ := strconv.ParseFloat(m[1], 64)
	serial := m[2]
	groupKey := fmt.Sprintf("%s:%s", m[1], serial)

	// Extract Record Type: "type=SYSCALL" etc.
	recType := "UNKNOWN"
	if idx := strings.Index(line, "type="); idx != -1 {
		rest := line[idx+5:]
		if spaceIdx := strings.Index(rest, " "); spaceIdx != -1 {
			recType = rest[:spaceIdx]
		}
	}

	kvMap := make(map[string]string)
	matches := reAuditKV.FindAllStringSubmatch(line, -1)
	for _, match := range matches {
		k := match[1]
		v := match[2]
		if v == "" {
			v = match[3]
		}
		kvMap[k] = v
	}

	c.mu.Lock()
	group, exists := c.groups[groupKey]
	if !exists {
		group = &auditRecordGroup{
			Timestamp: tsFloat,
			Serial:    serial,
			Records:   make(map[string]map[string]string),
			RawLines:  make([]string, 0, 4),
		}
		c.groups[groupKey] = group
	}
	group.Records[recType] = kvMap
	group.RawLines = append(group.RawLines, line)
	group.LastSeen = time.Now()

	// If this record is PROCTITLE or CWD, the group is typically complete
	if recType == "PROCTITLE" {
		item := c.compileGroupToRawItem(group)
		delete(c.groups, groupKey)
		c.mu.Unlock()

		select {
		case out <- item:
		default:
		}
		return
	}
	c.mu.Unlock()
}

func (c *LinuxAuditdCollector) compileGroupToRawItem(group *auditRecordGroup) RawLogItem {
	payload := make(map[string]interface{})
	payload["timestamp"] = group.Timestamp
	payload["serial"] = group.Serial

	// Aggregate records
	for recType, kv := range group.Records {
		payload[strings.ToLower(recType)] = kv
	}

	// 1. Process CommandLine Extraction & Hex Decoding
	var commandLineParts []string
	if execve, ok := group.Records["EXECVE"]; ok {
		argc, _ := strconv.Atoi(execve["argc"])
		for i := 0; i < argc; i++ {
			argKey := fmt.Sprintf("a%d", i)
			if argVal, exists := execve[argKey]; exists {
				decoded := decodeHexIfApplicable(argVal)
				commandLineParts = append(commandLineParts, decoded)
			}
		}
	}

	// Fallback to PROCTITLE if EXECVE was absent or truncated
	if len(commandLineParts) == 0 {
		if proctitle, ok := group.Records["PROCTITLE"]; ok {
			if titleHex, ok := proctitle["proctitle"]; ok {
				decoded := decodeHexProctitle(titleHex)
				if decoded != "" {
					commandLineParts = append(commandLineParts, decoded)
				}
			}
		}
	}

	fullCmd := strings.Join(commandLineParts, " ")
	payload["decoded_command_line"] = fullCmd

	// 2. Extract PID and enrich via /proc
	var pidStr string
	if syscallRec, ok := group.Records["SYSCALL"]; ok {
		pidStr = syscallRec["pid"]
		payload["pid"] = pidStr
		payload["ppid"] = syscallRec["ppid"]
		payload["exe"] = syscallRec["exe"]
		payload["uid"] = syscallRec["uid"]
		payload["euid"] = syscallRec["euid"]
		payload["syscall_number"] = syscallRec["syscall"]
		payload["success"] = syscallRec["success"]
	}

	if pidStr != "" {
		enrichFromProc(pidStr, payload)
	}

	// Construct ISO timestamp
	sec := int64(group.Timestamp)
	nsec := int64((group.Timestamp - float64(sec)) * 1e9)
	t := time.Unix(sec, nsec).UTC()

	return RawLogItem{
		EventID:        generateUUID(),
		SourceChannel:  "auditd",
		SourceEventID:  group.Serial,
		EventTimestamp: t.Format(time.RFC3339Nano),
		RawPayload:     payload,
		RawText:        strings.Join(group.RawLines, "\n"),
	}
}

func decodeHexIfApplicable(s string) string {
	s = strings.Trim(s, `"'`)
	// Check if even length hex string
	if len(s)%2 == 0 && isHex(s) {
		bytes, err := hex.DecodeString(s)
		if err == nil && len(bytes) > 0 {
			return string(bytes)
		}
	}
	return s
}

func decodeHexProctitle(s string) string {
	s = strings.Trim(s, `"'`)
	if len(s)%2 != 0 || !isHex(s) {
		return s
	}
	bytes, err := hex.DecodeString(s)
	if err != nil {
		return s
	}
	// Replace null bytes with spaces
	for i, b := range bytes {
		if b == 0 {
			bytes[i] = ' '
		}
	}
	return strings.TrimSpace(string(bytes))
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}

func enrichFromProc(pidStr string, payload map[string]interface{}) {
	procPath := filepath.Join("/proc", pidStr)
	if _, err := os.Stat(procPath); err != nil {
		return // process already exited
	}

	// Read symlink to executable
	exeTarget, err := os.Readlink(filepath.Join(procPath, "exe"))
	if err == nil && exeTarget != "" {
		payload["proc_exe_path"] = exeTarget

		// Hash file if size < 10MB
		if fi, err := os.Stat(exeTarget); err == nil && fi.Size() < 10*1024*1024 {
			if f, err := os.Open(exeTarget); err == nil {
				h := sha256.New()
				if _, err := io.Copy(h, f); err == nil {
					payload["proc_exe_sha256"] = hex.EncodeToString(h.Sum(nil))
				}
				f.Close()
			}
		}
	}
}
