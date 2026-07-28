package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"qwdtt/internal/qwdtt"
)

func main() {
	configPath := flag.String("config", "/opt/etc/qwdtt/config.json", "qWDTT configuration")
	flag.Parse()
	cfg, err := qwdtt.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("qwdtt config: %v", err)
	}
	if cfg.WebListen == "" {
		cfg.WebListen = "0.0.0.0:3333"
	}
	logs := qwdtt.NewLogBook()
	logs.Add("INFO", "qWDTT server starting")
	runtime := qwdtt.NewRuntime(&cfg, *configPath, logs)
	fmt.Printf("qWDTT UI listening on %s mode=%s routing=%s\n", cfg.WebListen, cfg.Mode, cfg.Routing.Mode)
	go func() {
		server := &http.Server{
			Addr:              cfg.WebListen,
			Handler:           qwdtt.WebHandler(&cfg, *configPath, logs, runtime),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		if err := server.ListenAndServe(); err != nil {
			log.Printf("web: %v", err)
		}
	}()
	if err := runtime.Start(context.Background()); err != nil {
		log.Fatalf("transport: %v", err)
	}
	select {}
}
