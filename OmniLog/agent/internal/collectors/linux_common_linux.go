//go:build linux

package collectors

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

type fileOffsetState struct {
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
}

// LinuxCommonCollector tails auth.log, syslog, and journald with inode/offset persistence.
type LinuxCommonCollector struct {
	mu         sync.Mutex
	stateFile  string
	offsets    map[string]fileOffsetState
	stopCh     chan struct{}
	cancelFunc context.CancelFunc
}

// NewLinuxCommonCollector creates Linux log tailer with persistence.
func NewLinuxCommonCollector(stateFile string) *LinuxCommonCollector {
	if stateFile == "" {
		stateFile = "./data/offsets.json"
	}
	c := &LinuxCommonCollector{
		stateFile: stateFile,
		offsets:   make(map[string]fileOffsetState),
		stopCh:    make(chan struct{}),
	}
	c.loadOffsets()
	return c
}

func (c *LinuxCommonCollector) Name() string {
	return "linux_common_collector"
}

func (c *LinuxCommonCollector) loadOffsets() {
	data, err := os.ReadFile(c.stateFile)
	if err == nil {
		_ = json.Unmarshal(data, &c.offsets)
	}
}

func (c *LinuxCommonCollector) saveOffsets() {
	data, err := json.MarshalIndent(c.offsets, "", "  ")
	if err == nil {
		_ = os.MkdirAll(filepath.Dir(c.stateFile), 0755)
		_ = os.WriteFile(c.stateFile+".tmp", data, 0644)
		_ = os.Rename(c.stateFile+".tmp", c.stateFile)
	}
}

func (c *LinuxCommonCollector) Start(ctx context.Context, out chan<- RawLogItem) error {
	ctx, cancel := context.WithCancel(ctx)
	c.cancelFunc = cancel

	// 1. Identify auth log path
	authPath := "/var/log/auth.log"
	if _, err := os.Stat(authPath); os.IsNotExist(err) {
		if _, err := os.Stat("/var/log/secure"); err == nil {
			authPath = "/var/log/secure"
		}
	}

	// 2. Identify syslog path
	syslogPath := "/var/log/syslog"
	if _, err := os.Stat(syslogPath); os.IsNotExist(err) {
		if _, err := os.Stat("/var/log/messages"); err == nil {
			syslogPath = "/var/log/messages"
		}
	}

	go c.tailFile(ctx, authPath, "auth", out)
	go c.tailFile(ctx, syslogPath, "syslog", out)
	go c.streamJournald(ctx, out)

	return nil
}

func (c *LinuxCommonCollector) Stop() error {
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
	c.saveOffsets()
	return nil
}

func (c *LinuxCommonCollector) tailFile(ctx context.Context, path string, channel string, out chan<- RawLogItem) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.readAvailableBytes(path, channel, out)
		}
	}
}

func (c *LinuxCommonCollector) readAvailableBytes(path string, channel string, out chan<- RawLogItem) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return
	}

	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	currentInode := stat.Ino
	currentSize := fileInfo.Size()

	c.mu.Lock()
	st, exists := c.offsets[path]
	if !exists || st.Inode != currentInode || st.Offset > currentSize {
		// New file or rotated log
		st = fileOffsetState{Inode: currentInode, Offset: currentSize} // tail from end if fresh, or 0
		if !exists {
			// Read last 16KB on startup if file is large
			if currentSize > 16384 {
				st.Offset = currentSize - 16384
			} else {
				st.Offset = 0
			}
		} else {
			st.Offset = 0
		}
		c.offsets[path] = st
	}
	c.mu.Unlock()

	if currentSize <= st.Offset {
		return
	}

	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	if _, err := file.Seek(st.Offset, io.SeekStart); err != nil {
		return
	}

	scanner := bufio.NewScanner(file)
	newOffset := st.Offset

	for scanner.Scan() {
		line := scanner.Text()
		newOffset += int64(len(scanner.Bytes())) + 1

		if strings.TrimSpace(line) == "" {
			continue
		}

		item := c.parseLinuxLogLine(channel, line)
		select {
		case out <- item:
		default:
		}
	}

	c.mu.Lock()
	c.offsets[path] = fileOffsetState{Inode: currentInode, Offset: newOffset}
	c.saveOffsets()
	c.mu.Unlock()
}

var (
	reSSHAccepted = regexp.MustCompile(`Accepted (password|publickey) for (\S+) from (\S+) port (\d+)`)
	reSSHFailed   = regexp.MustCompile(`Failed (password|publickey) for (?:invalid user )?(\S+) from (\S+) port (\d+)`)
	reSudo        = regexp.MustCompile(`(\S+) : TTY=(\S+) ; PWD=(\S+) ; USER=(\S+) ; COMMAND=(.*)`)
	reUFW         = regexp.MustCompile(`\[UFW BLOCK\] IN=(\S*).*SRC=(\S+).*DST=(\S+).*PROTO=(\S+)`)
)

func (c *LinuxCommonCollector) parseLinuxLogLine(channel, line string) RawLogItem {
	payload := make(map[string]interface{})
	payload["raw_line"] = line
	payload["channel"] = channel

	// SSH Authentication analysis
	if strings.Contains(line, "sshd") {
		if m := reSSHAccepted.FindStringSubmatch(line); len(m) == 5 {
			payload["event_type"] = "ssh_login_success"
			payload["auth_method"] = m[1]
			payload["user"] = m[2]
			payload["src_ip"] = m[3]
			payload["src_port"] = m[4]
		} else if m := reSSHFailed.FindStringSubmatch(line); len(m) == 5 {
			payload["event_type"] = "ssh_login_failure"
			payload["auth_method"] = m[1]
			payload["user"] = m[2]
			payload["src_ip"] = m[3]
			payload["src_port"] = m[4]
		}
	}

	// Sudo Execution analysis
	if strings.Contains(line, "sudo:") {
		if m := reSudo.FindStringSubmatch(line); len(m) == 6 {
			payload["event_type"] = "sudo_execution"
			payload["actor_user"] = m[1]
			payload["tty"] = m[2]
			payload["pwd"] = m[3]
			payload["target_user"] = m[4]
			payload["command"] = m[5]
		}
	}

	// Firewall UFW block
	if strings.Contains(line, "[UFW BLOCK]") {
		if m := reUFW.FindStringSubmatch(line); len(m) == 5 {
			payload["event_type"] = "firewall_block"
			payload["in_interface"] = m[1]
			payload["src_ip"] = m[2]
			payload["dst_ip"] = m[3]
			payload["protocol"] = strings.ToLower(m[4])
		}
	}

	return RawLogItem{
		EventID:        generateUUID(),
		SourceChannel:  channel,
		EventTimestamp: time.Now().UTC().Format(time.RFC3339Nano),
		RawPayload:     payload,
		RawText:        line,
	}
}

func (c *LinuxCommonCollector) streamJournald(ctx context.Context, out chan<- RawLogItem) {
	cmd := exec.CommandContext(ctx, "journalctl", "-o", "json", "-f", "-n", "0")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var jEntry map[string]interface{}
		if err := json.Unmarshal(line, &jEntry); err == nil {
			ts := time.Now().UTC().Format(time.RFC3339Nano)
			if realtime, ok := jEntry["__REALTIME_TIMESTAMP"].(string); ok {
				if usec, err := fmt.Sscanf(realtime, "%d"); err == nil && usec > 0 {
					// timestamp available
				}
			}

			item := RawLogItem{
				EventID:        generateUUID(),
				SourceChannel:  "journald",
				EventTimestamp: ts,
				RawPayload:     jEntry,
				RawText:        string(line),
			}

			select {
			case out <- item:
			default:
			}
		}
	}
	_ = cmd.Wait()
}
