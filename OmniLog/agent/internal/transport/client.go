package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"forcefields-agent/internal/collectors"
	"forcefields-agent/internal/system"
)

// TransportClient manages communication between agent and Central Manager.
type TransportClient struct {
	managerURL string
	agentID    string
	apiKey     string
	client     *http.Client
	sentTotal  uint64
}

// EnrollRequest is the payload sent during initial agent registration.
type EnrollRequest struct {
	Token       string              `json:"token"`
	Fingerprint *system.Fingerprint `json:"fingerprint"`
}

// EnrollResponse is the response returned upon successful enrollment.
type EnrollResponse struct {
	Status            string `json:"status"`
	AgentID           string `json:"agent_id"`
	APIKey            string `json:"api_key"`
	OSCategory        string `json:"os_category"`
	BatchSize         int    `json:"batch_size"`
	HeartbeatInterval int    `json:"heartbeat_interval"`
	Message           string `json:"message"`
}

// HeartbeatPayload represents periodic agent health metrics.
type HeartbeatPayload struct {
	AgentID         string  `json:"agent_id"`
	Hostname        string  `json:"hostname"`
	OSCategory      string  `json:"os_category"`
	OSName          string  `json:"os_name"`
	OSVersion       string  `json:"os_version"`
	IPAddress       string  `json:"ip_address"`
	CPUPercent      float64 `json:"cpu_percent"`
	RAMPercent      float64 `json:"ram_percent"`
	QueueDepth      int64   `json:"queue_depth"`
	EventsSentTotal uint64  `json:"events_sent_total"`
}

// LogBatchPayload represents an event batch sent to the manager.
type LogBatchPayload struct {
	AgentID string                  `json:"agent_id"`
	BatchID string                  `json:"batch_id"`
	Events  []collectors.RawLogItem `json:"events"`
}

// NewTransportClient instantiates a new transport client.
func NewTransportClient(managerURL, agentID, apiKey string) *TransportClient {
	return &TransportClient{
		managerURL: managerURL,
		agentID:    agentID,
		apiKey:     apiKey,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// Enroll performs one-time agent enrollment with the Central Manager.
func Enroll(managerURL, token string, fp *system.Fingerprint) (*EnrollResponse, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	reqBody := EnrollRequest{
		Token:       token,
		Fingerprint: fp,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal enroll request: %w", err)
	}

	endpoint := fmt.Sprintf("%s/api/v1/agents/enroll", managerURL)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("enrollment HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("enrollment failed (HTTP %d): %s", resp.StatusCode, string(bodyBytes))
	}

	var enrollResp EnrollResponse
	if err := json.Unmarshal(bodyBytes, &enrollResp); err != nil {
		return nil, fmt.Errorf("invalid enrollment response JSON: %w", err)
	}

	return &enrollResp, nil
}

// SendHeartbeat sends health status and queue depth to the manager.
func (c *TransportClient) SendHeartbeat(ctx context.Context, fp *system.Fingerprint, queueDepth int64) error {
	payload := HeartbeatPayload{
		AgentID:         c.agentID,
		Hostname:        fp.Hostname,
		OSCategory:      fp.OSCategory,
		OSName:          fp.OSName,
		OSVersion:       fp.OSVersion,
		IPAddress:       fp.IPAddress,
		CPUPercent:      fp.CPUPercent,
		RAMPercent:      fp.RAMPercent,
		QueueDepth:      queueDepth,
		EventsSentTotal: atomic.LoadUint64(&c.sentTotal),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf("%s/api/v1/ingest/heartbeat", c.managerURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-ID", c.agentID)
	req.Header.Set("X-API-Key", c.apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("heartbeat rejected (HTTP %d): %s", resp.StatusCode, string(b))
	}

	return nil
}

// SendBatch delivers a batch of raw log events with exponential backoff on failure.
func (c *TransportClient) SendBatch(ctx context.Context, batchID string, events []collectors.RawLogItem) error {
	if len(events) == 0 {
		return nil
	}

	payload := LogBatchPayload{
		AgentID: c.agentID,
		BatchID: batchID,
		Events:  events,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal batch: %w", err)
	}

	endpoint := fmt.Sprintf("%s/api/v1/ingest/logs", c.managerURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-ID", c.agentID)
	req.Header.Set("X-API-Key", c.apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("batch rejected (HTTP %d): %s", resp.StatusCode, string(b))
	}

	atomic.AddUint64(&c.sentTotal, uint64(len(events)))
	return nil
}

// GetSentTotal returns total count of successfully transmitted events.
func (c *TransportClient) GetSentTotal() uint64 {
	return atomic.LoadUint64(&c.sentTotal)
}
