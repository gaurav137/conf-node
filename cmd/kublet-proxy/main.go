package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/gaurav137/conf-inferencing/internal/kubletproxy"
	"github.com/gaurav137/conf-inferencing/internal/kubletproxy/admission"
)

func main() {
	os.Exit(run())
}

func run() int {
	cfg := &kubletproxy.Config{}

	flag.StringVar(&cfg.KubeconfigPath, "kubeconfig", "", "Path to kubeconfig file for API server connection (required)")
	flag.StringVar(&cfg.KubeconfigContext, "context", "", "Context to use from kubeconfig (optional, uses current-context if empty)")
	flag.StringVar(&cfg.ListenAddr, "listen-addr", ":6443", "Address to listen on for kubelet connections")
	flag.StringVar(&cfg.TLSCertFile, "tls-cert", "", "Path to TLS certificate file for serving")
	flag.StringVar(&cfg.TLSKeyFile, "tls-key", "", "Path to TLS key file for serving")
	flag.StringVar(&cfg.AdmissionPolicyFile, "admission-policy", "", "Path to admission policy file (optional)")
	flag.BoolVar(&cfg.LogRequests, "log-requests", true, "Log all proxied requests")
	flag.BoolVar(&cfg.LogPodPayloads, "log-pod-payloads", false, "Log full pod payloads for pod creation requests")
	flag.Parse()

	if cfg.KubeconfigPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --kubeconfig is required")
		flag.Usage()
		return 1
	}

	// Load kubeconfig
	if err := cfg.LoadKubeconfigFromFile(); err != nil {
		fmt.Fprintf(os.Stderr, "Error loading kubeconfig: %v\n", err)
		return 1
	}

	// Create admission controller
	var admissionController admission.Controller
	if cfg.AdmissionPolicyFile != "" {
		var err error
		admissionController, err = admission.NewPolicyController(cfg.AdmissionPolicyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading admission policy: %v\n", err)
			return 1
		}
	} else {
		// Default to allowing all pods but logging them
		admissionController = admission.NewLoggingController()
	}

	// Create and configure proxy
	proxy, err := kubletproxy.New(cfg, admissionController)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating proxy: %v\n", err)
		return 1
	}

	// Setup signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		fmt.Printf("\nReceived signal %v, shutting down...\n", sig)
		cancel()
	}()

	// Start proxy
	fmt.Printf("Starting kublet-proxy...\n")
	fmt.Printf("  Listening on: %s\n", cfg.ListenAddr)
	fmt.Printf("  API Server: %s\n", cfg.LoadedKubeConfig.Server)
	fmt.Printf("  TLS: %v\n", cfg.TLSCertFile != "")

	if err := proxy.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error running proxy: %v\n", err)
		return 1
	}

	return 0
}
