package system

import (
	"net"
	"os"
	"strings"
)

// Fingerprint holds detailed host and OS identification data.
type Fingerprint struct {
	Hostname    string  `json:"hostname"`
	OSCategory  string  `json:"os_category"` // windows_workstation, windows_server, ubuntu_server, linux_endpoint
	OSName      string  `json:"os_name"`
	OSVersion   string  `json:"os_version"`
	IPAddress   string  `json:"ip_address"`
	MACAddress  string  `json:"mac_address"`
	CPUPercent  float64 `json:"cpu_percent"`
	RAMPercent  float64 `json:"ram_percent"`
	TotalRAMMB  uint64  `json:"total_ram_mb"`
	FreeRAMMB   uint64  `json:"free_ram_mb"`
}

// GetPrimaryNetworkInfo returns the primary non-loopback IPv4 and MAC address.
func GetPrimaryNetworkInfo() (string, string) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "127.0.0.1", "00:00:00:00:00:00"
	}

	for _, iface := range interfaces {
		// Skip loopback, down, or virtual interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		nameLower := strings.ToLower(iface.Name)
		if strings.Contains(nameLower, "docker") || strings.Contains(nameLower, "veth") || strings.Contains(nameLower, "br-") {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip != nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				mac := iface.HardwareAddr.String()
				if mac == "" {
					mac = "00:00:00:00:00:00"
				}
				return ip.String(), mac
			}
		}
	}

	return "127.0.0.1", "00:00:00:00:00:00"
}

// GetHostname returns clean system hostname.
func GetHostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "UNKNOWN-HOST"
	}
	return h
}
