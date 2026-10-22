package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tcarwash/arap/internal/buildinfo"
	"github.com/tcarwash/arap/keyserver"
)

func main() {
	if len(os.Args) >= 2 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		if len(os.Args) == 3 && os.Args[2] == "--json" {
			_ = json.NewEncoder(os.Stdout).Encode(buildinfo.For("arap-keyserver"))
			return
		}
		if len(os.Args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: arap-keyserver version [--json]")
			os.Exit(2)
		}
		info := buildinfo.For("arap-keyserver")
		fmt.Printf("ARAP keyserver %s (commit %s)\n", info.Version, info.Commit)
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		healthcheck()
		return
	}
	root := os.Getenv("ARAP_DATA_DIR")
	if root == "" {
		root = "./arap-data"
	}
	token := os.Getenv("ARAP_UPLOAD_TOKEN")
	if err := keyserver.ValidateUploadToken(token); err != nil {
		log.Fatal(err)
	}
	addr := os.Getenv("ARAP_LISTEN")
	if addr == "" {
		addr = ":8080"
	}
	options, err := serverOptionsFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	handler, err := keyserver.NewWithOptions(root, token, options)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := handler.Close(); err != nil {
			log.Printf("close keyserver storage: %v", err)
		}
	}()
	srv := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024}
	stopped := make(chan os.Signal, 1)
	signal.Notify(stopped, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopped
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("shutdown: %v", err)
		}
	}()
	log.Printf("ARAP object/key server listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func serverOptionsFromEnv() (keyserver.Options, error) {
	options := keyserver.DefaultOptions()
	for _, item := range []struct {
		name string
		dest *int64
	}{
		{"ARAP_MAX_PROOF_OBJECTS", &options.MaxProofObjects},
		{"ARAP_MAX_KEY_OBJECTS", &options.MaxKeyObjects},
		{"ARAP_MAX_TOTAL_BYTES", &options.MaxTotalBytes},
		{"ARAP_MAX_UPLOADS_PER_MINUTE", &options.MaxUploadsPerMinute},
	} {
		value := os.Getenv(item.name)
		if value == "" {
			continue
		}
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil || parsed <= 0 {
			return keyserver.Options{}, fmt.Errorf("%s must be a positive integer", item.name)
		}
		*item.dest = parsed
	}
	if value := os.Getenv("ARAP_RETENTION_DAYS"); value != "" {
		days, err := strconv.ParseInt(value, 10, 64)
		if err != nil || days < 0 || days > int64((1<<63-1)/int64(24*time.Hour)) {
			return keyserver.Options{}, fmt.Errorf("ARAP_RETENTION_DAYS must be a non-negative integer within duration range")
		}
		options.Retention = time.Duration(days) * 24 * time.Hour
	}
	return options, nil
}

func healthcheck() {
	url := os.Getenv("ARAP_HEALTHCHECK_URL")
	if url == "" {
		addr := os.Getenv("ARAP_LISTEN")
		if addr == "" || strings.HasPrefix(addr, ":") {
			addr = "127.0.0.1:8080"
		}
		url = "http://" + addr + "/healthz"
	}
	if err := checkHealth(url); err != nil {
		log.Fatal(err)
	}
}

func checkHealth(url string) error {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health endpoint returned %s", resp.Status)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 16))
	return nil
}
