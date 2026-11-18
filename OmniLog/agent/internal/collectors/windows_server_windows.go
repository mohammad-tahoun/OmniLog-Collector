//go:build windows

package collectors

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// WindowsServerCollector collects enterprise Server channels: Active Directory, Kerberos, RDP, and Firewall.
type WindowsServerCollector struct {
	mu           sync.Mutex
	channels     []string
	lastRecordID map[string]uint64
	stopCh       chan struct{}
}

// NewWindowsServerCollector initializes Windows Server telemetry collector.
func NewWindowsServerCollector() *WindowsServerCollector {
	return &WindowsServerCollector{
		channels: []string{
			"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
			"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
			"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
			"DNS Server",
		},
		lastRecordID: make(map[string]uint64),
		stopCh:       make(chan struct{}),
	}
}

func (c *WindowsServerCollector) Name() string {
	return "windows_server_collector"
}

func (c *WindowsServerCollector) Start(ctx context.Context, out chan<- RawLogItem) error {
	for _, ch := range c.channels {
		c.initLatestRecordID(ch)
	}

	ticker := time.NewTicker(2 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-c.stopCh:
				return
			case <-ticker.C:
				for _, ch := range c.channels {
					c.pollChannel(ch, out)
				}
			}
		}
	}()

	return nil
}

func (c *WindowsServerCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.stopCh:
		return nil
	default:
		close(c.stopCh)
	}
	return nil
}

func (c *WindowsServerCollector) initLatestRecordID(channel string) {
	cmd := exec.Command("wevtutil", "qe", channel, "/c:1", "/rd:true", "/f:xml")
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		c.lastRecordID[channel] = 0
		return
	}

	var evt WindowsEventXML
	if err := xml.Unmarshal(out, &evt); err == nil && evt.System.EventRecordID > 0 {
		c.lastRecordID[channel] = evt.System.EventRecordID
	}
}

func (c *WindowsServerCollector) pollChannel(channel string, out chan<- RawLogItem) {
	c.mu.Lock()
	lastID := c.lastRecordID[channel]
	c.mu.Unlock()

	var xpath string
	if lastID > 0 {
		xpath = fmt.Sprintf("*[System[(EventRecordID > %d)]]", lastID)
	} else {
		xpath = "*[System]"
	}

	cmd := exec.Command("wevtutil", "qe", channel, fmt.Sprintf("/q:%s", xpath), "/c:50", "/rd:false", "/f:xml")
	outBytes, err := cmd.Output()
	if err != nil || len(outBytes) == 0 {
		return
	}

	xmlContent := string(outBytes)
	xmlContent = strings.TrimSpace(xmlContent)
	if xmlContent == "" {
		return
	}

	decoder := xml.NewDecoder(bytes.NewReader([]byte("<Events>" + xmlContent + "</Events>")))
	var maxSeen uint64 = lastID

	for {
		t, err := decoder.Token()
		if err != nil {
			break
		}

		switch se := t.(type) {
		case xml.StartElement:
			if se.Name.Local == "Event" {
				var evt WindowsEventXML
				if err := decoder.DecodeElement(&evt, &se); err == nil {
					if evt.System.EventRecordID > maxSeen {
						maxSeen = evt.System.EventRecordID
					}

					rawItem := c.convertServerEvent(channel, evt)
					select {
					case out <- rawItem:
					default:
					}
				}
			}
		}
	}

	if maxSeen > lastID {
		c.mu.Lock()
		c.lastRecordID[channel] = maxSeen
		c.mu.Unlock()
	}
}

func (c *WindowsServerCollector) convertServerEvent(channel string, evt WindowsEventXML) RawLogItem {
	payload := make(map[string]interface{})

	payload["provider_name"] = evt.System.Provider.Name
	payload["provider_guid"] = evt.System.Provider.GUID
	payload["event_id"] = evt.System.EventID
	payload["level"] = evt.System.Level
	payload["task"] = evt.System.Task
	payload["opcode"] = evt.System.Opcode
	payload["channel"] = evt.System.Channel
	payload["computer"] = evt.System.Computer
	payload["record_id"] = evt.System.EventRecordID
	payload["process_id"] = evt.System.Execution.ProcessID
	payload["thread_id"] = evt.System.Execution.ThreadID
	payload["user_sid"] = evt.System.Security.UserID

	eventDataMap := make(map[string]string)
	for _, d := range evt.EventData.Data {
		if d.Name != "" {
			eventDataMap[d.Name] = d.Value
			payload[d.Name] = d.Value
		}
	}
	payload["event_data"] = eventDataMap

	ts := evt.System.TimeCreated.SystemTime
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339Nano)
	}

	return RawLogItem{
		EventID:        generateUUID(),
		SourceChannel:  channel,
		SourceEventID:  evt.System.EventID,
		EventTimestamp: ts,
		RawPayload:     payload,
	}
}
