//go:build windows

package collectors

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// WindowsEventXML maps the native Windows Event Log rendered XML format.
type WindowsEventXML struct {
	XMLName xml.Name `xml:"Event"`
	System  struct {
		Provider struct {
			Name string `xml:"Name,attr"`
			GUID string `xml:"Guid,attr"`
		} `xml:"Provider"`
		EventID       string `xml:"EventID"`
		Version       string `xml:"Version"`
		Level         string `xml:"Level"`
		Task          string `xml:"Task"`
		Opcode        string `xml:"Opcode"`
		Keywords      string `xml:"Keywords"`
		TimeCreated   struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		EventRecordID uint64 `xml:"EventRecordID"`
		Execution     struct {
			ProcessID uint32 `xml:"ProcessID,attr"`
			ThreadID  uint32 `xml:"ThreadID,attr"`
		} `xml:"Execution"`
		Channel  string `xml:"Channel"`
		Computer string `xml:"Computer"`
		Security struct {
			UserID string `xml:"UserID,attr"`
		} `xml:"Security"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
	UserData struct {
		InnerXML string `xml:",innerxml"`
	} `xml:"UserData"`
}

// WindowsCommonCollector collects Sysmon, Security, PowerShell, System & Application logs.
type WindowsCommonCollector struct {
	mu           sync.Mutex
	channels     []string
	lastRecordID map[string]uint64
	stopCh       chan struct{}
}

// NewWindowsCommonCollector initializes standard Windows telemetry collectors.
func NewWindowsCommonCollector() *WindowsCommonCollector {
	return &WindowsCommonCollector{
		channels: []string{
			"Microsoft-Windows-Sysmon/Operational",
			"Security",
			"Microsoft-Windows-PowerShell/Operational",
			"System",
			"Application",
		},
		lastRecordID: make(map[string]uint64),
		stopCh:       make(chan struct{}),
	}
}

func (c *WindowsCommonCollector) Name() string {
	return "windows_common_collector"
}

func (c *WindowsCommonCollector) Start(ctx context.Context, out chan<- RawLogItem) error {
	// Initialize latest record IDs so we collect fresh events on start
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

func (c *WindowsCommonCollector) Stop() error {
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

func (c *WindowsCommonCollector) initLatestRecordID(channel string) {
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

func (c *WindowsCommonCollector) pollChannel(channel string, out chan<- RawLogItem) {
	c.mu.Lock()
	lastID := c.lastRecordID[channel]
	c.mu.Unlock()

	var xpath string
	if lastID > 0 {
		xpath = fmt.Sprintf("*[System[(EventRecordID > %d)]]", lastID)
	} else {
		// Collect last 25 events if starting from 0
		xpath = "*[System]"
	}

	cmd := exec.Command("wevtutil", "qe", channel, fmt.Sprintf("/q:%s", xpath), "/c:50", "/rd:false", "/f:xml")
	outBytes, err := cmd.Output()
	if err != nil || len(outBytes) == 0 {
		return
	}

	// Wevtutil outputs concatenated <Event>...</Event> blocks wrapped or unadorned
	xmlContent := string(outBytes)
	xmlContent = strings.TrimSpace(xmlContent)
	if xmlContent == "" {
		return
	}

	// Wrap in root tag for robust XML decoder
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

					rawItem := c.convertWindowsEvent(channel, evt)
					select {
					case out <- rawItem:
					default:
						// Non-blocking write
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

func (c *WindowsCommonCollector) convertWindowsEvent(channel string, evt WindowsEventXML) RawLogItem {
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



func parseUint64(s string) uint64 {
	n, _ := strconv.ParseUint(s, 10, 64)
	return n
}

func dummyHex(s string) string {
	return hex.EncodeToString([]byte(s))
}
