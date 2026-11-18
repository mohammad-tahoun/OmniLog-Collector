package collectors

import (
	"context"
	"crypto/rand"
	"fmt"
)

// RawLogItem represents a captured OS log event before transmission to the Central Manager.
type RawLogItem struct {
	EventID        string                 `json:"event_id"`
	SourceChannel  string                 `json:"source_channel"`
	SourceEventID  string                 `json:"source_event_id,omitempty"`
	EventTimestamp string                 `json:"event_timestamp"` // UTC ISO-8601
	RawPayload     map[string]interface{} `json:"raw_payload"`
	RawText        string                 `json:"raw_text,omitempty"`
}

// Collector defines the lifecycle methods for dedicated OS event collectors.
type Collector interface {
	Name() string
	Start(ctx context.Context, out chan<- RawLogItem) error
	Stop() error
}

// generateUUID returns a cryptographically secure RFC 4122 v4 UUID string.
func generateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
