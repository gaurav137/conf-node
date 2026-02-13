package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/gaurav137/conf-node/pkg/attestation"
)

// AttestResponse is the JSON response returned by the /attest endpoint.
type AttestResponse struct {
	TPMQuote  string `json:"tpmQuote"`  // base64-encoded TPM quote (quoted + signature)
	HCLReport string `json:"hclReport"` // base64-encoded HCL report blob
	SNPReport string `json:"snpReport"` // base64-encoded AMD SNP attestation report
	AIKCert   string `json:"aikCert"`   // base64-encoded AIK x.509 certificate (DER)
}

func main() {
	addr := flag.String("addr", ":8900", "listen address (host:port)")
	flag.Parse()

	http.HandleFunc("/attest", attestHandler)

	fmt.Printf("attestation-server listening on %s\n", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}

func attestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Use a default nonce; callers can supply one via ?nonce=<base64> query param.
	nonce := []byte("external-verifier-nonce")
	if q := r.URL.Query().Get("nonce"); q != "" {
		decoded, err := base64.StdEncoding.DecodeString(q)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid base64 nonce: %v", err), http.StatusBadRequest)
			return
		}
		nonce = decoded
	}

	evidence, err := attestation.CollectEvidence(nonce)
	if err != nil {
		log.Printf("attestation failed: %v", err)
		http.Error(w, fmt.Sprintf("attestation failed: %v", err), http.StatusInternalServerError)
		return
	}

	resp := AttestResponse{
		TPMQuote:  base64.StdEncoding.EncodeToString(evidence.TPMQuote),
		HCLReport: base64.StdEncoding.EncodeToString(evidence.HCLReport),
		SNPReport: base64.StdEncoding.EncodeToString(evidence.SNPReport),
	}
	if evidence.AIKCert != nil {
		resp.AIKCert = base64.StdEncoding.EncodeToString(evidence.AIKCert)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
