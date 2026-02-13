// Package attestation provides core TPM attestation functionality for Azure
// Confidential VMs. It reads the Azure-provisioned AIK, generates TPM quotes,
// and retrieves the HCL/SNP attestation report from vTPM NVRAM.
package attestation

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"log"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

const (
	// TPMDevice is the default TPM resource manager device path.
	TPMDevice = "/dev/tpmrm0"

	// AIKPersistentHandle is the Azure CVM pre-provisioned AIK public key handle.
	AIKPersistentHandle = 0x81000003

	// AIKCertNVIndex is the NV index holding the AIK x.509 certificate.
	AIKCertNVIndex = 0x01C101D0

	// HCLReportNVIndex is the NV index where the HCL firmware stores
	// the SNP attestation report on Azure CVMs.
	HCLReportNVIndex = 0x01400001

	// HCLReportHeaderSize is the size of the HCL header before the SNP report.
	HCLReportHeaderSize = 32

	// SNPReportSize is the size of the raw AMD SNP attestation report.
	SNPReportSize = 1184
)

// Evidence holds the collected attestation artifacts from an Azure CVM.
type Evidence struct {
	TPMQuote  []byte // Marshalled TPM quote (quoted + signature)
	QuoteHash [32]byte
	HCLReport []byte // Full HCL report blob from NVRAM
	SNPReport []byte // Raw AMD SNP report extracted from HCL report
	AIKCert   []byte // AIK x.509 certificate (DER), may be nil
}

// CollectEvidence opens the TPM, reads the Azure-provisioned AIK, generates
// a TPM Quote over PCRs 0-7 using the given nonce, and retrieves the HCL/SNP
// report from vTPM NVRAM.
func CollectEvidence(nonce []byte) (*Evidence, error) {
	// 1. Open TPM
	tpmDev, err := linuxtpm.Open(TPMDevice)
	if err != nil {
		return nil, fmt.Errorf("open TPM: %w", err)
	}
	defer tpmDev.Close()

	return collectEvidenceFromTPM(tpmDev, nonce)
}

// collectEvidenceFromTPM performs the attestation using an already-opened TPM.
func collectEvidenceFromTPM(tpm transport.TPM, nonce []byte) (*Evidence, error) {
	akHandle := tpm2.TPMHandle(AIKPersistentHandle)

	// 2. Read the pre-provisioned AIK
	akName, exists := ReadPersistentHandle(tpm, akHandle)
	if !exists {
		return nil, fmt.Errorf("Azure-provisioned AIK not found at handle 0x%08x", AIKPersistentHandle)
	}
	log.Println("Azure-provisioned AIK found.")

	// 3. Read AIK certificate from NV index
	aikCert, err := NVRead(tpm, tpm2.TPMHandle(AIKCertNVIndex))
	if err != nil {
		log.Printf("Warning: could not read AIK cert from NV 0x%08x: %v", AIKCertNVIndex, err)
	} else {
		log.Printf("AIK certificate: %d bytes", len(aikCert))
	}

	// 4. Generate TPM Quote over PCRs 0-7
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
					PCRSelect: tpm2.PCClientCompatible.PCRs(0, 1, 2, 3, 4, 5, 6, 7),
				},
			},
		},
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("TPM Quote: %w", err)
	}

	quotedBytes := tpm2.Marshal(quoteRsp.Quoted)
	sigBytes := tpm2.Marshal(quoteRsp.Signature)

	var quoteBlob bytes.Buffer
	quoteBlob.Write(quotedBytes)
	quoteBlob.Write(sigBytes)

	log.Println("TPM Quote generated.")

	// 5. Hash TPM Quote
	quoteHash := sha256.Sum256(quoteBlob.Bytes())
	log.Printf("SHA256(Quote): %x", quoteHash)

	// 6. Read HCL report from vTPM NVRAM (contains SNP report)
	hclBlob, err := GetHCLReport(tpm)
	if err != nil {
		return nil, fmt.Errorf("read HCL report: %w", err)
	}
	log.Printf("HCL report size: %d bytes", len(hclBlob))

	if len(hclBlob) < HCLReportHeaderSize+SNPReportSize {
		return nil, fmt.Errorf("HCL report too small (%d bytes), expected at least %d",
			len(hclBlob), HCLReportHeaderSize+SNPReportSize)
	}
	snpReport := hclBlob[HCLReportHeaderSize : HCLReportHeaderSize+SNPReportSize]
	log.Printf("SNP report extracted: %d bytes", len(snpReport))

	return &Evidence{
		TPMQuote:  quoteBlob.Bytes(),
		QuoteHash: quoteHash,
		HCLReport: hclBlob,
		SNPReport: snpReport,
		AIKCert:   aikCert,
	}, nil
}

// ReadPersistentHandle reads the public area of a persistent TPM handle.
// Returns the name and true if the handle exists.
func ReadPersistentHandle(tpm transport.TPM, handle tpm2.TPMHandle) (tpm2.TPM2BName, bool) {
	readPub, err := tpm2.ReadPublic{
		ObjectHandle: handle,
	}.Execute(tpm)
	if err != nil {
		return tpm2.TPM2BName{}, false
	}
	return readPub.Name, true
}

// GetHCLReport reads the HCL report from vTPM NVRAM at the well-known NV index.
// The HCL firmware on Azure CVMs writes the SNP attestation report here at boot.
// The data has a 32-byte header followed by the raw 1184-byte AMD SNP report.
// Equivalent to: tpm2_nvread -C o 0x01400001
func GetHCLReport(tpm transport.TPM) ([]byte, error) {
	return NVRead(tpm, tpm2.TPMHandle(HCLReportNVIndex))
}

// NVRead reads the full contents of any NV index in chunks (TPM max NV buffer
// is typically 1024 bytes). Equivalent to: tpm2_nvread -C o <index>
func NVRead(tpm transport.TPM, nvIndex tpm2.TPMHandle) ([]byte, error) {
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
	log.Printf("NV index 0x%08x: %d bytes", nvIndex, totalSize)

	// Read NV data in chunks
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
