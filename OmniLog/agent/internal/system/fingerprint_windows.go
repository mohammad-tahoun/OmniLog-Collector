//go:build windows

package system

import (
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	modKernel32             = syscall.NewLazyDLL("kernel32.dll")
	modAdvapi32             = syscall.NewLazyDLL("advapi32.dll")
	procGlobalMemoryStatusEx = modKernel32.NewProc("GlobalMemoryStatusEx")
	procGetSystemTimes       = modKernel32.NewProc("GetSystemTimes")
	procRegOpenKeyExW        = modAdvapi32.NewProc("RegOpenKeyExW")
	procRegQueryValueExW     = modAdvapi32.NewProc("RegQueryValueExW")
	procRegCloseKey          = modAdvapi32.NewProc("RegCloseKey")
)

type memorystatusex struct {
	cbSize                  uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

type filetime struct {
	dwLowDateTime  uint32
	dwHighDateTime uint32
}

var (
	lastIdleTime   uint64
	lastKernelTime uint64
	lastUserTime   uint64
	hasPrevTimes   bool
)

func filetimeToUint64(ft filetime) uint64 {
	return (uint64(ft.dwHighDateTime) << 32) | uint64(ft.dwLowDateTime)
}

func readRegistryString(subKey string, valueName string) (string, error) {
	const HKEY_LOCAL_MACHINE = 0x80000002
	const KEY_READ = 0x20019

	pSubKey, err := syscall.UTF16PtrFromString(subKey)
	if err != nil {
		return "", err
	}
	pValueName, err := syscall.UTF16PtrFromString(valueName)
	if err != nil {
		return "", err
	}

	var hKey uintptr
	r1, _, _ := procRegOpenKeyExW.Call(
		uintptr(HKEY_LOCAL_MACHINE),
		uintptr(unsafe.Pointer(pSubKey)),
		0,
		uintptr(KEY_READ),
		uintptr(unsafe.Pointer(&hKey)),
	)
	if r1 != 0 {
		return "", fmt.Errorf("RegOpenKeyExW failed: %d", r1)
	}
	defer procRegCloseKey.Call(hKey)

	var valType uint32
	var bufSize uint32 = 1024
	buf := make([]uint16, bufSize/2)

	r1, _, _ = procRegQueryValueExW.Call(
		hKey,
		uintptr(unsafe.Pointer(pValueName)),
		0,
		uintptr(unsafe.Pointer(&valType)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufSize)),
	)
	if r1 != 0 {
		return "", fmt.Errorf("RegQueryValueExW failed: %d", r1)
	}

	return syscall.UTF16ToString(buf), nil
}

// CollectFingerprint gathers complete hardware & OS metadata for Windows systems.
func CollectFingerprint() (*Fingerprint, error) {
	hostname := GetHostname()
	ip, mac := GetPrimaryNetworkInfo()

	// Read OS details from Windows Registry
	productName, _ := readRegistryString(`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "ProductName")
	displayVersion, _ := readRegistryString(`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "DisplayVersion")
	currentBuild, _ := readRegistryString(`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "CurrentBuild")
	installationType, _ := readRegistryString(`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "InstallationType")

	if productName == "" {
		productName = "Windows"
	}
	osVersion := productName
	if displayVersion != "" {
		osVersion += fmt.Sprintf(" %s", displayVersion)
	}
	if currentBuild != "" {
		osVersion += fmt.Sprintf(" (Build %s)", currentBuild)
	}

	// Classify: Windows Workstation vs Windows Server
	isServer := false
	instLower := strings.ToLower(installationType)
	prodLower := strings.ToLower(productName)
	if strings.Contains(instLower, "server") || strings.Contains(prodLower, "server") {
		isServer = true
	}

	osCategory := "windows_workstation"
	if isServer {
		osCategory = "windows_server"
	}

	// Read Memory
	var mem memorystatusex
	mem.cbSize = uint32(unsafe.Sizeof(mem))
	r1, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&mem)))

	var totalMB, freeMB uint64
	var ramPercent float64
	if r1 != 0 {
		totalMB = mem.ullTotalPhys / (1024 * 1024)
		freeMB = mem.ullAvailPhys / (1024 * 1024)
		ramPercent = float64(mem.dwMemoryLoad)
	}

	// Calculate CPU usage
	cpuPercent := calculateWindowsCPU()

	return &Fingerprint{
		Hostname:   hostname,
		OSCategory: osCategory,
		OSName:     productName,
		OSVersion:  osVersion,
		IPAddress:  ip,
		MACAddress: mac,
		CPUPercent: cpuPercent,
		RAMPercent: ramPercent,
		TotalRAMMB: totalMB,
		FreeRAMMB:  freeMB,
	}, nil
}

func calculateWindowsCPU() float64 {
	var idleTime, kernelTime, userTime filetime
	r1, _, _ := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idleTime)),
		uintptr(unsafe.Pointer(&kernelTime)),
		uintptr(unsafe.Pointer(&userTime)),
	)
	if r1 == 0 {
		return 0.0
	}

	idle := filetimeToUint64(idleTime)
	kernel := filetimeToUint64(kernelTime)
	user := filetimeToUint64(userTime)

	if !hasPrevTimes {
		lastIdleTime = idle
		lastKernelTime = kernel
		lastUserTime = user
		hasPrevTimes = true
		time.Sleep(20 * time.Millisecond)
		return 1.5 // sensible initial sample
	}

	idleDiff := idle - lastIdleTime
	kernelDiff := kernel - lastKernelTime
	userDiff := user - lastUserTime

	lastIdleTime = idle
	lastKernelTime = kernel
	lastUserTime = user

	total := kernelDiff + userDiff
	if total == 0 {
		return 0.0
	}

	busy := total - idleDiff
	pct := (float64(busy) / float64(total)) * 100.0
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return pct
}
