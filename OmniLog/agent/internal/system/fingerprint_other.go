//go:build !windows && !linux

package system

// CollectFingerprint is a generic fallback for other operating systems.
func CollectFingerprint() (*Fingerprint, error) {
	hostname := GetHostname()
	ip, mac := GetPrimaryNetworkInfo()

	return &Fingerprint{
		Hostname:   hostname,
		OSCategory: "linux_endpoint",
		OSName:     "Generic OS",
		OSVersion:  "1.0",
		IPAddress:  ip,
		MACAddress: mac,
		CPUPercent: 1.0,
		RAMPercent: 25.0,
		TotalRAMMB: 8192,
		FreeRAMMB:  6144,
	}, nil
}
