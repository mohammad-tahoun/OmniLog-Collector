//go:build !windows

package collectors

import (
	"context"
)

// WindowsServerCollector stub for Linux / non-Windows builds.
type WindowsServerCollector struct{}

func NewWindowsServerCollector() *WindowsServerCollector {
	return &WindowsServerCollector{}
}

func (c *WindowsServerCollector) Name() string {
	return "windows_server_collector_stub"
}

func (c *WindowsServerCollector) Start(ctx context.Context, out chan<- RawLogItem) error {
	return nil
}

func (c *WindowsServerCollector) Stop() error {
	return nil
}
