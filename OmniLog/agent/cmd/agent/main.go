package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"forcefields-agent/internal/buffer"
	"forcefields-agent/internal/collectors"
	"forcefields-agent/internal/config"
	"forcefields-agent/internal/system"
	"forcefields-agent/internal/transport"
)

var (
	flagEnroll    = flag.Bool("enroll", false, "Enroll agent with Central Manager")
	flagManager   = flag.String("manager", "", "Central Manager URL (e.g. http://192.168.1.50:8000)")
	flagToken     = flag.String("token", "", "Enrollment authentication token")
	flagConfig    = flag.String("config", "agent.yaml", "Path to agent configuration file")
	flagInstall   = flag.Bool("install-service", false, "Install as OS background daemon / service")
	flagUninstall = flag.Bool("uninstall-service", false, "Uninstall OS background daemon / service")
	flagRun       = flag.Bool("run", false, "Run telemetry agent in foreground")
)

func main() {
	flag.Parse()

	if *flagInstall {
		handleInstallService()
		return
	}

	if *flagUninstall {
		handleUninstallService()
		return
	}

	if *flagEnroll {
		handleEnrollment()
		return
	}

	// Default run mode
	runAgent()
}

func handleEnrollment() {
	managerURL := *flagManager
	token := *flagToken

	if managerURL == "" {
		// Attempt reading existing config if manager URL flag not provided
		if cfg, err := config.LoadConfig(*flagConfig); err == nil && cfg.ManagerURL != "" {
			managerURL = cfg.ManagerURL
		} else {
			log.Fatalf("[-] Manager URL is required for enrollment. Use --manager http://<IP>:8000")
		}
	}

	if token == "" {
		token = "FORCEFIELDS-DEFAULT-ENROLL-KEY"
	}

	log.Printf("[+] Fingerprinting local host hardware and operating system...")
	fp, err := system.CollectFingerprint()
	if err != nil {
		log.Fatalf("[-] Failed to collect system fingerprint: %v", err)
	}

	log.Printf("[*] Host: %s | OS: %s | Detected Category: %s | Primary IP: %s",
		fp.Hostname, fp.OSVersion, fp.OSCategory, fp.IPAddress)

	log.Printf("[+] Contacting Central Manager at %s for enrollment...", managerURL)
	resp, err := transport.Enroll(managerURL, token, fp)
	if err != nil {
		log.Fatalf("[-] Enrollment failed: %v", err)
	}

	cfg := &config.AgentConfig{
		AgentID:           resp.AgentID,
		ManagerURL:        managerURL,
		APIKey:            resp.APIKey,
		OSCategory:        resp.OSCategory,
		BatchSize:         resp.BatchSize,
		HeartbeatInterval: resp.HeartbeatInterval,
		QueueDir:          "./data/queue",
		StateFile:         "./data/offsets.json",
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = 10
	}

	if err := config.SaveConfig(*flagConfig, cfg); err != nil {
		log.Fatalf("[-] Failed to save config to %s: %v", *flagConfig, err)
	}

	log.Printf("[SUCCESS] Agent successfully enrolled!")
	log.Printf("    -> Agent ID:    %s", resp.AgentID)
	log.Printf("    -> OS Category: %s", resp.OSCategory)
	log.Printf("    -> Config saved to: %s", *flagConfig)
	log.Printf("[+] You can now run the agent with: ./forcefields-agent --run (or --install-service)")
}

func runAgent() {
	log.Println("==========================================================")
	log.Println("   FORCE-FIELDS DEDICATED TELEMETRY AGENT (STAGE 1 SOC)   ")
	log.Println("==========================================================")

	cfg, err := config.LoadConfig(*flagConfig)
	if err != nil || cfg.AgentID == "" || cfg.APIKey == "" {
		log.Printf("[!] Valid enrollment configuration not found at '%s'.", *flagConfig)
		log.Println("[!] Please enroll first: ./forcefields-agent --enroll --manager http://<IP>:8000 --token <TOKEN>")
		os.Exit(1)
	}

	fp, err := system.CollectFingerprint()
	if err != nil {
		log.Fatalf("[-] System fingerprint error: %v", err)
	}
	if cfg.OSCategory != "" {
		fp.OSCategory = cfg.OSCategory
	}

	log.Printf("[+] Agent ID:    %s", cfg.AgentID)
	log.Printf("[+] Manager:     %s", cfg.ManagerURL)
	log.Printf("[+] Hostname:    %s", fp.Hostname)
	log.Printf("[+] OS Category: %s (%s)", fp.OSCategory, fp.OSVersion)
	log.Printf("[+] Primary IP:  %s | MAC: %s", fp.IPAddress, fp.MACAddress)

	// Initialize Local Persistent Store-and-Forward Queue
	diskQueue, err := buffer.NewDiskQueue(cfg.QueueDir, cfg.BatchSize)
	if err != nil {
		log.Fatalf("[-] Failed to initialize disk queue at %s: %v", cfg.QueueDir, err)
	}
	defer diskQueue.Close()
	log.Printf("[+] Persistent disk queue active at '%s' (buffered depth: %d)", cfg.QueueDir, diskQueue.Depth())

	// Initialize Transport Client
	transClient := transport.NewTransportClient(cfg.ManagerURL, cfg.AgentID, cfg.APIKey)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle Graceful Termination
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("\n[*] Shutdown signal received. Flushing buffers and stopping collectors...")
		cancel()
	}()

	// Event Ingestion Channel
	eventCh := make(chan collectors.RawLogItem, 1000)

	// Enqueue Worker: writes incoming events to persistent disk queue
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case item, ok := <-eventCh:
				if !ok {
					return
				}
				if err := diskQueue.Enqueue(item); err != nil {
					log.Printf("[-] Failed to buffer event to disk: %v", err)
				}
			}
		}
	}()

	// Start OS-Specific Collectors
	startCollectors(ctx, fp.OSCategory, cfg.StateFile, eventCh)

	// Heartbeat Worker: sends heartbeat periodically
	go runHeartbeatWorker(ctx, transClient, diskQueue, cfg.HeartbeatInterval)

	// Batch Log Sender Worker: flushes disk queue to Central Manager
	go runBatchSenderWorker(ctx, transClient, diskQueue, cfg.BatchSize)

	log.Println("[+] Force-Fields Agent running. Zero-loss telemetry active.")
	<-ctx.Done()
	time.Sleep(500 * time.Millisecond)
	log.Println("[+] Agent stopped cleanly.")
}

func startCollectors(ctx context.Context, osCategory, stateFile string, out chan<- collectors.RawLogItem) {
	if runtime.GOOS == "windows" {
		log.Println("[+] Activating Windows Common Collector (Sysmon, Security, PowerShell, System)...")
		winCommon := collectors.NewWindowsCommonCollector()
		if err := winCommon.Start(ctx, out); err != nil {
			log.Printf("[-] Error starting Windows Common Collector: %v", err)
		}

		if osCategory == "windows_server" {
			log.Println("[+] Activating Windows Server Collector (Active Directory, Kerberos, RDP, Firewall)...")
			winServer := collectors.NewWindowsServerCollector()
			if err := winServer.Start(ctx, out); err != nil {
				log.Printf("[-] Error starting Windows Server Collector: %v", err)
			}
		}
	} else if runtime.GOOS == "linux" {
		log.Printf("[+] Activating Linux Common Collector (auth.log, syslog, journald) for %s...", osCategory)
		linuxCommon := collectors.NewLinuxCommonCollector(stateFile)
		if err := linuxCommon.Start(ctx, out); err != nil {
			log.Printf("[-] Error starting Linux Common Collector: %v", err)
		}

		log.Println("[+] Activating Linux Auditd Collector (multi-line aggregator + hex decoder + /proc enrichment)...")
		auditdColl := collectors.NewLinuxAuditdCollector("/var/log/audit/audit.log", "./data/auditd_offset.json")
		if err := auditdColl.Start(ctx, out); err != nil {
			log.Printf("[-] Error starting Auditd Collector: %v", err)
		}
	} else {
		log.Printf("[!] Generic OS platform detected (%s). Standard collectors bypassed.", runtime.GOOS)
	}
}

func runHeartbeatWorker(ctx context.Context, client *transport.TransportClient, q *buffer.DiskQueue, intervalSec int) {
	if intervalSec <= 0 {
		intervalSec = 10
	}
	ticker := time.NewTicker(time.Duration(intervalSec) * time.Second)
	defer ticker.Stop()

	// Send immediate initial heartbeat
	if fp, err := system.CollectFingerprint(); err == nil {
		_ = client.SendHeartbeat(ctx, fp, q.Depth())
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fp, err := system.CollectFingerprint()
			if err != nil {
				continue
			}
			depth := q.Depth()
			if err := client.SendHeartbeat(ctx, fp, depth); err != nil {
				log.Printf("[!] Heartbeat warning: %v", err)
			}
		}
	}
}

func runBatchSenderWorker(ctx context.Context, client *transport.TransportClient, q *buffer.DiskQueue, batchSize int) {
	if batchSize <= 0 {
		batchSize = 100
	}

	backoff := 1 * time.Second
	maxBackoff := 30 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		default:
			// Check if we have items buffered
			items, maxSeq, err := q.PeekBatch(batchSize)
			if err != nil || len(items) == 0 {
				time.Sleep(500 * time.Millisecond)
				continue
			}

			batchID := fmt.Sprintf("batch-%d-%d", time.Now().UnixNano(), len(items))
			err = client.SendBatch(ctx, batchID, items)
			if err != nil {
				// Manager unreachable or offline: back off exponentially and keep items safe on disk
				log.Printf("[!] Ingestion endpoint unreachable (%v). Backing off %v. Buffering events locally.", err, backoff)
				time.Sleep(backoff)
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				continue
			}

			// Success: commit sequence on disk
			_ = q.AckBatch(maxSeq)
			backoff = 1 * time.Second
		}
	}
}

func handleInstallService() {
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("[-] Unable to determine executable path: %v", err)
	}
	exePath, _ = filepath.Abs(exePath)

	if runtime.GOOS == "windows" {
		log.Println("[+] Installing ForceFieldsAgent as a native Windows Service...")
		cmd := exec.Command("sc.exe", "create", "ForceFieldsAgent",
			fmt.Sprintf("binPath= \"%s --run\"", exePath),
			"start= auto",
			"DisplayName= Force-Fields Telemetry Agent")
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Fatalf("[-] Service install failed: %v\nOutput: %s", err, string(out))
		}
		log.Printf("[+] Service installed successfully. Starting service...\n%s", string(out))
		_ = exec.Command("sc.exe", "start", "ForceFieldsAgent").Run()
	} else if runtime.GOOS == "linux" {
		log.Println("[+] Creating systemd service file at /etc/systemd/system/forcefields-agent.service...")
		serviceContent := fmt.Sprintf(`[Unit]
Description=Force-Fields SOC Telemetry Agent
After=network.target auditd.service

[Service]
Type=simple
ExecStart=%s --run
Restart=always
RestartSec=5s
LimitNOFILE=65536
WorkingDirectory=%s

[Install]
WantedBy=multi-user.target
`, exePath, filepath.Dir(exePath))

		if err := os.WriteFile("/etc/systemd/system/forcefields-agent.service", []byte(serviceContent), 0644); err != nil {
			log.Fatalf("[-] Failed writing service file: %v", err)
		}

		_ = exec.Command("systemctl", "daemon-reload").Run()
		_ = exec.Command("systemctl", "enable", "forcefields-agent").Run()
		_ = exec.Command("systemctl", "start", "forcefields-agent").Run()
		log.Println("[+] systemd service forcefields-agent installed and started.")
	} else {
		log.Printf("[!] Service installation not supported on %s", runtime.GOOS)
	}
}

func handleUninstallService() {
	if runtime.GOOS == "windows" {
		log.Println("[+] Removing Windows Service ForceFieldsAgent...")
		_ = exec.Command("sc.exe", "stop", "ForceFieldsAgent").Run()
		out, err := exec.Command("sc.exe", "delete", "ForceFieldsAgent").CombinedOutput()
		if err != nil {
			log.Fatalf("[-] Service uninstall failed: %v\n%s", err, string(out))
		}
		log.Println("[+] Service uninstalled.")
	} else if runtime.GOOS == "linux" {
		log.Println("[+] Removing systemd service forcefields-agent...")
		_ = exec.Command("systemctl", "stop", "forcefields-agent").Run()
		_ = exec.Command("systemctl", "disable", "forcefields-agent").Run()
		_ = os.Remove("/etc/systemd/system/forcefields-agent.service")
		_ = exec.Command("systemctl", "daemon-reload").Run()
		log.Println("[+] systemd service uninstalled.")
	}
}
