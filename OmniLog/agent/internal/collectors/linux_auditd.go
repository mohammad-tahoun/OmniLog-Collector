//go:build !linux

package collectors

import (
	"context"
)

// LinuxAuditdCollector stub for Windows / non-Linux builds.
type LinuxAuditdCollector struct{}

func NewLinuxAuditdCollector(auditLogPath, stateFile string) *LinuxAuditdCollector {
	return &LinuxAuditdCollector{}
}

func (c *LinuxAuditdCollector) Name() string {
	return "linux_auditd_collector_stub"
}

func (c *LinuxAuditdCollector) Start(ctx context.Context, out chan<- RawLogItem) error {
	return nil
}

func (c *LinuxAuditdCollector) Stop() error {
	return nil
}
