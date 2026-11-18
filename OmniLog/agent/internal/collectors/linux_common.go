//go:build !linux

package collectors

import (
	"context"
)

// LinuxCommonCollector stub for Windows / non-Linux builds.
type LinuxCommonCollector struct{}

func NewLinuxCommonCollector(stateFile string) *LinuxCommonCollector {
	return &LinuxCommonCollector{}
}

func (c *LinuxCommonCollector) Name() string {
	return "linux_common_collector_stub"
}

func (c *LinuxCommonCollector) Start(ctx context.Context, out chan<- RawLogItem) error {
	return nil
}

func (c *LinuxCommonCollector) Stop() error {
	return nil
}
