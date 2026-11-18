//go:build linux

package system

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	lastLinuxIdle  uint64
	lastLinuxTotal uint64
	hasPrevLinux   bool
)

// CollectFingerprint gathers complete hardware & OS metadata for Linux systems.
func CollectFingerprint() (*Fingerprint, error) {
	hostname := GetHostname()
	ip, mac := GetPrimaryNetworkInfo()

	osInfo := parseOSRelease()
	osCategory := classifyLinuxOS(osInfo)

	totalMB, freeMB, ramPct := readLinuxMemory()
	cpuPct := calculateLinuxCPU()

	osName := osInfo["NAME"]
	if osName == "" {
		osName = "Linux"
	}
	osVersion := osInfo["PRETTY_NAME"]
	if osVersion == "" {
		osVersion = fmt.Sprintf("%s %s", osName, osInfo["VERSION_ID"])
	}

	return &Fingerprint{
		Hostname:   hostname,
		OSCategory: osCategory,
		OSName:     osName,
		OSVersion:  osVersion,
		IPAddress:  ip,
		MACAddress: mac,
		CPUPercent: cpuPct,
		RAMPercent: ramPct,
		TotalRAMMB: totalMB,
		FreeRAMMB:  freeMB,
	}, nil
}

func parseOSRelease() map[string]string {
	data := make(map[string]string)
	file, err := os.Open("/etc/os-release")
	if err != nil {
		file, err = os.Open("/usr/lib/os-release")
		if err != nil {
			return data
		}
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			v := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
			data[k] = v
		}
	}
	return data
}

func classifyLinuxOS(osInfo map[string]string) string {
	id := strings.ToLower(osInfo["ID"])
	idLike := strings.ToLower(osInfo["ID_LIKE"])
	pretty := strings.ToLower(osInfo["PRETTY_NAME"])

	isUbuntu := id == "ubuntu" || strings.Contains(idLike, "ubuntu")

	if isUbuntu {
		// Ubuntu Server check
		if strings.Contains(pretty, "server") {
			return "ubuntu_server"
		}
		// Check display manager - absence indicates server environment
		if _, err := os.Stat("/usr/bin/Xorg"); os.IsNotExist(err) {
			if _, err := os.Stat("/usr/bin/wayland"); os.IsNotExist(err) {
				return "ubuntu_server"
			}
		}
		// Default Ubuntu installations in SOC / cloud labs are ubuntu_server
		return "ubuntu_server"
	}

	return "linux_endpoint"
}

func readLinuxMemory() (uint64, uint64, float64) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, 0.0
	}
	defer file.Close()

	var memTotalKB, memAvailableKB uint64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			key := strings.TrimSuffix(fields[0], ":")
			val, _ := strconv.ParseUint(fields[1], 10, 64)
			if key == "MemTotal" {
				memTotalKB = val
			} else if key == "MemAvailable" {
				memAvailableKB = val
			}
		}
	}

	if memTotalKB == 0 {
		return 0, 0, 0.0
	}

	totalMB := memTotalKB / 1024
	freeMB := memAvailableKB / 1024
	usedKB := memTotalKB - memAvailableKB
	pct := (float64(usedKB) / float64(memTotalKB)) * 100.0

	return totalMB, freeMB, pct
}

func calculateLinuxCPU() float64 {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return 0.0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) < 5 {
				return 0.0
			}

			var user, nice, system, idle, iowait, irq, softirq, steal uint64
			user, _ = strconv.ParseUint(fields[1], 10, 64)
			nice, _ = strconv.ParseUint(fields[2], 10, 64)
			system, _ = strconv.ParseUint(fields[3], 10, 64)
			idle, _ = strconv.ParseUint(fields[4], 10, 64)
			if len(fields) > 5 {
				iowait, _ = strconv.ParseUint(fields[5], 10, 64)
			}
			if len(fields) > 6 {
				irq, _ = strconv.ParseUint(fields[6], 10, 64)
			}
			if len(fields) > 7 {
				softirq, _ = strconv.ParseUint(fields[7], 10, 64)
			}
			if len(fields) > 8 {
				steal, _ = strconv.ParseUint(fields[8], 10, 64)
			}

			idleAll := idle + iowait
			systemAll := system + irq + softirq
			virtAll := steal
			total := user + nice + systemAll + idleAll + virtAll

			if !hasPrevLinux {
				lastLinuxIdle = idleAll
				lastLinuxTotal = total
				hasPrevLinux = true
				time.Sleep(20 * time.Millisecond)
				return 2.0
			}

			totalDiff := total - lastLinuxTotal
			idleDiff := idleAll - lastLinuxIdle

			lastLinuxIdle = idleAll
			lastLinuxTotal = total

			if totalDiff == 0 {
				return 0.0
			}

			pct := (float64(totalDiff-idleDiff) / float64(totalDiff)) * 100.0
			if pct < 0 {
				pct = 0
			}
			if pct > 100 {
				pct = 100
			}
			return pct
		}
	}

	return 0.0
}
