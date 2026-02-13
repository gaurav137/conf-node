package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"log"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

const (
	tpmDevice = "/dev/tpmrm0"

	// Azure CVM pre-provisioned AIK (Attestation Identity Key)
	aikPersistentHandle = 0x81000003 // AIK_PUB_INDEX — AIK public key
	aikCertNVIndex      = 0x01C101D0 // AIK_CERT_INDEX — AIK certificate (x.509)

	// HCL report NV index — the HCL firmware stores the SNP attestation
	// report in vTPM NVRAM at this well-known index on Azure CVMs.
	hclReportNVIndex    = 0x01400001
	hclReportHeaderSize = 32   // bytes of HCL header before the SNP report
	snpReportSize       = 1184 // bytes of the raw AMD SNP attestation report
)

func main() {

	// --------------------------------------------
	// 1. Open TPM
	// --------------------------------------------
	tpmDev, err := linuxtpm.Open(tpmDevice)
	if err != nil {
		log.Fatalf("OpenTPM failed: %v", err)
	}
	defer tpmDev.Close()

	akHandle := tpm2.TPMHandle(aikPersistentHandle)

	// --------------------------------------------
	// 2. Read the pre-provisioned AIK
	//    On Azure CVMs the HCL firmware creates an AIK at 0x81000003.
	// --------------------------------------------
	akName, exists := readPersistentHandle(tpmDev, akHandle)
	if !exists {
		log.Fatalf("Azure-provisioned AIK not found at handle 0x%08x", aikPersistentHandle)
	}
	fmt.Println("Azure-provisioned AIK found.")

	// --------------------------------------------
	// 3. Read AIK certificate from NV index
	// --------------------------------------------
	aikCert, err := nvRead(tpmDev, tpm2.TPMHandle(aikCertNVIndex))
	if err != nil {
		log.Printf("Warning: could not read AIK cert from NV 0x%08x: %v", aikCertNVIndex, err)
	} else {
		fmt.Printf("AIK certificate: %d bytes\n", len(aikCert))
	}

	// --------------------------------------------
	// 4. Generate TPM Quote
	// --------------------------------------------
	nonce := []byte("external-verifier-nonce")

	quoteRsp, err := tpm2.Quote{
		SignHandle: tpm2.AuthHandle{
			Handle: akHandle,
			Name:   akName,
			Auth:   tpm2.PasswordAuth(nil),
		},
		QualifyingData: tpm2.TPM2BData{Buffer: nonce},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgNull,
		},
		PCRSelect: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(0, 7),
				},
			},
		},
	}.Execute(tpmDev)
	if err != nil {
		log.Fatalf("Quote failed: %v", err)
	}

	quotedBytes := tpm2.Marshal(quoteRsp.Quoted)
	sigBytes := tpm2.Marshal(quoteRsp.Signature)

	var quoteBlob bytes.Buffer
	quoteBlob.Write(quotedBytes)
	quoteBlob.Write(sigBytes)

	fmt.Println("TPM Quote generated.")

	// --------------------------------------------
	// 5. Hash TPM Quote
	// --------------------------------------------
	hash := sha256.Sum256(quoteBlob.Bytes())
	fmt.Printf("SHA256(Quote): %x\n", hash)

	// --------------------------------------------
	// 6. Read HCL report from vTPM NVRAM (contains SNP report)
	//    On Azure CVMs the HCL firmware pre-generates the SNP
	//    attestation report at boot and stores it at NV index 0x01400001.
	// --------------------------------------------
	hclBlob, err := getHCLReport(tpmDev)
	if err != nil {
		log.Fatalf("Failed to read HCL report: %v", err)
	}
	fmt.Printf("HCL report size: %d bytes\n", len(hclBlob))

	if len(hclBlob) < hclReportHeaderSize+snpReportSize {
		log.Fatalf("HCL report too small (%d bytes), expected at least %d",
			len(hclBlob), hclReportHeaderSize+snpReportSize)
	}
	snpReport := hclBlob[hclReportHeaderSize : hclReportHeaderSize+snpReportSize]
	fmt.Printf("SNP report extracted: %d bytes\n", len(snpReport))

	// --------------------------------------------
	// 7. Save artifacts
	// --------------------------------------------
	os.WriteFile("tpm_quote.bin", quoteBlob.Bytes(), 0644)
	os.WriteFile("hcl_report.bin", hclBlob, 0644)
	os.WriteFile("snp_report.bin", snpReport, 0644)
	if aikCert != nil {
		os.WriteFile("aik_cert.der", aikCert, 0644)
		fmt.Println("Saved tpm_quote.bin, hcl_report.bin, snp_report.bin, and aik_cert.der")
	} else {
		fmt.Println("Saved tpm_quote.bin, hcl_report.bin, and snp_report.bin")
	}
}

// ------------------------------------------------------------
// Helper: Read persistent handle's public area and name.
// Returns the name and true if the handle exists.
// ------------------------------------------------------------
func readPersistentHandle(tpm transport.TPM, handle tpm2.TPMHandle) (tpm2.TPM2BName, bool) {
	readPub, err := tpm2.ReadPublic{
		ObjectHandle: handle,
	}.Execute(tpm)
	if err != nil {
		return tpm2.TPM2BName{}, false
	}
	return readPub.Name, true
}

// ------------------------------------------------------------
// Read the HCL report from vTPM NVRAM at the well-known NV index.
// The HCL firmware on Azure CVMs writes the SNP attestation report
// here at boot time. The data has a 32-byte header followed by the
// raw 1184-byte AMD SNP report.
// Equivalent to: tpm2_nvread -C o 0x01400001
// ------------------------------------------------------------
func getHCLReport(tpm transport.TPM) ([]byte, error) {
	return nvRead(tpm, tpm2.TPMHandle(hclReportNVIndex))
}

// ------------------------------------------------------------
// Generic NV index reader — reads the full contents of any NV
// index in chunks (TPM max NV buffer is typically 1024 bytes).
// Equivalent to: tpm2_nvread -C o <index>
// ------------------------------------------------------------
func nvRead(tpm transport.TPM, nvIndex tpm2.TPMHandle) ([]byte, error) {

	// Read NV public to discover the data size and NV name
	nvPubRsp, err := tpm2.NVReadPublic{
		NVIndex: nvIndex,
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("NVReadPublic(0x%08x): %w", nvIndex, err)
	}

	nvPublic, err := nvPubRsp.NVPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("parse NV public: %w", err)
	}

	totalSize := int(nvPublic.DataSize)
	fmt.Printf("NV index 0x%08x: %d bytes\n", hclReportNVIndex, totalSize)

	// Read NV data in chunks (TPM max NV buffer is typically 1024 bytes)
	const maxChunk = 1024
	data := make([]byte, 0, totalSize)

	for offset := 0; offset < totalSize; {
		chunkSize := totalSize - offset
		if chunkSize > maxChunk {
			chunkSize = maxChunk
		}

		readRsp, err := tpm2.NVRead{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHOwner,
				Auth:   tpm2.PasswordAuth(nil),
			},
			NVIndex: tpm2.NamedHandle{
				Handle: nvIndex,
				Name:   nvPubRsp.NVName,
			},
			Size:   uint16(chunkSize),
			Offset: uint16(offset),
		}.Execute(tpm)
		if err != nil {
			return nil, fmt.Errorf("NVRead at offset %d: %w", offset, err)
		}

		data = append(data, readRsp.Data.Buffer...)
		offset += len(readRsp.Data.Buffer)
	}

	return data, nil
}
