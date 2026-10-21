// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func envString(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok && value != "" {
		return value
	}
	return fallback
}

func envInt(name string, fallback int) int {
	if value, err := strconv.Atoi(os.Getenv(name)); err == nil {
		return value
	}
	return fallback
}

func envDuration(name string, fallback time.Duration) time.Duration {
	if value, err := time.ParseDuration(os.Getenv(name)); err == nil {
		return value
	}
	return fallback
}

// runHealthcheck lets container runtimes probe the service without a shell or HTTP client in
// the image.
func runHealthcheck(arguments []string) int {
	flags := flag.NewFlagSet("healthcheck", flag.ExitOnError)
	target := flags.String("url", envString("EDEN_SYNCD_HEALTH_URL", "http://127.0.0.1:8787/healthz"),
		"health endpoint to probe")
	_ = flags.Parse(arguments)
	client := http.Client{Timeout: 3 * time.Second}
	response, err := client.Get(*target)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "unhealthy:", response.Status)
		return 1
	}
	return 0
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(runHealthcheck(os.Args[2:]))
	}

	dataDir := flag.String("data-dir", envString("EDEN_SYNCD_DATA", "./data"), "directory for objects and metadata")
	listenAddress := flag.String("listen", envString("EDEN_SYNCD_LISTEN", ":8787"), "HTTP listen address")
	token := flag.String("token", os.Getenv("EDEN_SYNCD_TOKEN"), "bearer token")
	adminToken := flag.String("admin-token", os.Getenv("EDEN_SYNCD_ADMIN_TOKEN"), "administrator token for the web dashboard")
	maxObjectMiB := flag.Int64("max-object-mib", int64(envInt("EDEN_SYNCD_MAX_OBJECT_MIB",
		int(defaultMaxObjectBytes/(1024*1024)))), "maximum object size in MiB")
	keepSnapshots := flag.Int("keep-snapshots", envInt("EDEN_SYNCD_KEEP_SNAPSHOTS", 0),
		"initial retention: newest snapshots kept per scope (0 = unlimited; dashboard settings take precedence)")
	keepDays := flag.Int("keep-days", envInt("EDEN_SYNCD_KEEP_DAYS", 0),
		"initial retention: keep snapshots younger than this many days (0 = unlimited)")
	maintenanceInterval := flag.Duration("maintenance-interval",
		envDuration("EDEN_SYNCD_MAINTENANCE_INTERVAL", 6*time.Hour),
		"how often retention and object garbage collection run (0 disables)")
	logFormat := flag.String("log-format", envString("EDEN_SYNCD_LOG_FORMAT", "text"), "log format: text or json")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}
	var logHandler slog.Handler = slog.NewTextHandler(os.Stderr, nil)
	if *logFormat == "json" {
		logHandler = slog.NewJSONHandler(os.Stderr, nil)
	}
	slog.SetDefault(slog.New(logHandler))

	s, err := newServerWithOptions(*dataDir, *token, *maxObjectMiB*1024*1024, serverOptions{
		adminToken: *adminToken,
		settings: serverSettings{Retention: retentionPolicy{
			KeepSnapshots: *keepSnapshots,
			KeepDays:      *keepDays,
		}},
	})
	if err != nil {
		slog.Error("start", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *maintenanceInterval > 0 {
		go s.maintenanceLoop(ctx, *maintenanceInterval)
	}

	httpServer := &http.Server{
		Addr:              *listenAddress,
		Handler:           s.handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	go func() {
		<-ctx.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownContext); err != nil {
			slog.Warn("shutdown", "error", err)
		}
	}()

	slog.Info("eden-syncd listening", "address", *listenAddress, "version", version,
		"data_dir", *dataDir, "dashboard", *adminToken != "")
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("serve", "error", err)
		os.Exit(1)
	}
	slog.Info("eden-syncd stopped")
}
