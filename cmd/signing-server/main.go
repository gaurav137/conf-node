package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// SigningServer holds the server state including the key pair
type SigningServer struct {
	privateKey *ecdsa.PrivateKey
	certPEM    []byte
	mu         sync.RWMutex
	generated  bool
}

// SignRequest is the request body for the /sign endpoint
type SignRequest struct {
	Payload string `json:"payload"`
}

// SignResponse is the response body for the /sign endpoint
type SignResponse struct {
	Signature string `json:"signature"`
}

// ErrorResponse is returned on errors
type ErrorResponse struct {
	Error string `json:"error"`
}

// NewSigningServer creates a new signing server instance
func NewSigningServer() *SigningServer {
	return &SigningServer{}
}

// GenerateKeys generates a new ECDSA key pair and self-signed certificate
func (s *SigningServer) GenerateKeys() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.generated {
		return nil // Keys already generated
	}

	// Generate ECDSA private key using P-256 curve
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create a self-signed certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "signing-server",
			Organization: []string{"kubelet-proxy"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	s.privateKey = privateKey
	s.certPEM = certPEM
	s.generated = true

	log.Println("Generated new ECDSA key pair and certificate")
	return nil
}

// Sign signs the given payload and returns the base64-encoded signature
func (s *SigningServer) Sign(payload string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.generated {
		return "", fmt.Errorf("keys not generated")
	}

	// Hash the payload
	hash := sha256.Sum256([]byte(payload))

	// Sign the hash
	signature, err := ecdsa.SignASN1(rand.Reader, s.privateKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign payload: %w", err)
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

// GetCertPEM returns the certificate in PEM format
func (s *SigningServer) GetCertPEM() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.generated {
		return nil, fmt.Errorf("keys not generated")
	}

	return s.certPEM, nil
}

// IsGenerated returns whether keys have been generated
func (s *SigningServer) IsGenerated() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.generated
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{Error: message})
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func main() {
	listenAddr := flag.String("listen-addr", ":8080", "Address to listen on")
	autoGenerate := flag.Bool("auto-generate", true, "Automatically generate keys on startup")
	flag.Parse()

	server := NewSigningServer()

	// Auto-generate keys on startup if enabled
	if *autoGenerate {
		if err := server.GenerateKeys(); err != nil {
			log.Fatalf("Failed to generate keys: %v", err)
		}
	}

	// Health check endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Generate keys endpoint
	http.HandleFunc("/generatekeys", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		if server.IsGenerated() {
			writeJSON(w, http.StatusOK, map[string]string{"status": "keys already generated"})
			return
		}

		if err := server.GenerateKeys(); err != nil {
			log.Printf("Failed to generate keys: %v", err)
			writeJSONError(w, http.StatusInternalServerError, "failed to generate keys")
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{"status": "keys generated"})
	})

	// Sign endpoint
	http.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		if !server.IsGenerated() {
			writeJSONError(w, http.StatusPreconditionFailed, "keys not generated")
			return
		}

		// Read the request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "failed to read request body")
			return
		}
		defer r.Body.Close()

		var req SignRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON request")
			return
		}

		if req.Payload == "" {
			writeJSONError(w, http.StatusBadRequest, "payload is required")
			return
		}

		signature, err := server.Sign(req.Payload)
		if err != nil {
			log.Printf("Failed to sign payload: %v", err)
			writeJSONError(w, http.StatusInternalServerError, "failed to sign payload")
			return
		}

		writeJSON(w, http.StatusOK, SignResponse{Signature: signature})
	})

	// Signing certificate endpoint
	http.HandleFunc("/signingcert", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		if !server.IsGenerated() {
			writeJSONError(w, http.StatusPreconditionFailed, "keys not generated")
			return
		}

		certPEM, err := server.GetCertPEM()
		if err != nil {
			log.Printf("Failed to get certificate: %v", err)
			writeJSONError(w, http.StatusInternalServerError, "failed to get certificate")
			return
		}

		w.Header().Set("Content-Type", "application/x-pem-file")
		w.WriteHeader(http.StatusOK)
		w.Write(certPEM)
	})

	log.Printf("Starting signing server on %s", *listenAddr)
	if err := http.ListenAndServe(*listenAddr, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
