//go:build !windows

package collectors

import (
	"context"
)

// WindowsCommonCollector stub for Linux / non-Windows builds.
type WindowsCommonCollector struct{}

func NewWindowsCommonCollector() *WindowsCommonCollector {
	return &WindowsCommonCollector{}
}

func (c *WindowsCommonCollector) Name() string {
	return "windows_common_collector_stub"
}

func (c *WindowsCommonCollector) Start(ctx context.Context, out chan<- RawLogItem) error {
	// No-op on non-Windows platforms
	return nil
}

func (c *WindowsCommonCollector) Stop() error {
	return nil
}
