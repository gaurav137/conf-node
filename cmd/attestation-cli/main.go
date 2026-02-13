package main

import (
	"fmt"
	"log"
	"os"

	"github.com/gaurav137/conf-node/pkg/attestation"
)

func main() {
	nonce := []byte("external-verifier-nonce")

	evidence, err := attestation.CollectEvidence(nonce)
	if err != nil {
		log.Fatalf("Attestation failed: %v", err)
	}

	fmt.Printf("SHA256(Quote): %x\n", evidence.QuoteHash)

	// Save artifacts
	os.WriteFile("tpm_quote.bin", evidence.TPMQuote, 0644)
	os.WriteFile("hcl_report.bin", evidence.HCLReport, 0644)
	os.WriteFile("snp_report.bin", evidence.SNPReport, 0644)
	if evidence.AIKCert != nil {
		os.WriteFile("aik_cert.der", evidence.AIKCert, 0644)
		fmt.Println("Saved tpm_quote.bin, hcl_report.bin, snp_report.bin, and aik_cert.der")
	} else {
		fmt.Println("Saved tpm_quote.bin, hcl_report.bin, and snp_report.bin")
	}
}
