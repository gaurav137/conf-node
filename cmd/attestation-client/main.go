package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

const (
	tpmDevice          = "/dev/tpmrm0"
	sevGuestReportPath = "/sys/kernel/security/sev-guest/report"
	akPersistentHandle = 0x81010001
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

	akHandle := tpm2.TPMHandle(akPersistentHandle)

	// --------------------------------------------
	// 2. Ensure AK exists (create if missing)
	// --------------------------------------------
	akName, exists := readPersistentHandle(tpmDev, akHandle)

	if !exists {
		fmt.Println("AK not found. Creating...")
		akName, err = createAndPersistAK(tpmDev, akHandle)
		if err != nil {
			log.Fatalf("Failed to create AK: %v", err)
		}
		fmt.Println("AK created and persisted.")
	} else {
		fmt.Println("AK already exists.")
	}

	// --------------------------------------------
	// 3. Generate TPM Quote
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
	// 4. Hash TPM Quote
	// --------------------------------------------
	hash := sha256.Sum256(quoteBlob.Bytes())
	fmt.Printf("SHA256(Quote): %x\n", hash)

	// --------------------------------------------
	// 5. Build 64-byte SNP report_data
	// --------------------------------------------
	reportData := make([]byte, 64)
	copy(reportData[0:32], hash[:])
	copy(reportData[32:], []byte("app-specific-data"))

	// --------------------------------------------
	// 6. Request SNP report via securityfs
	// --------------------------------------------
	f, err := os.OpenFile(sevGuestReportPath, os.O_RDWR, 0)
	if err != nil {
		log.Fatalf("Open SNP report path failed: %v", err)
	}
	defer f.Close()

	n, err := f.Write(reportData)
	if err != nil || n != 64 {
		log.Fatalf("Failed writing report_data")
	}

	var snpBuf bytes.Buffer
	_, err = io.Copy(&snpBuf, f)
	if err != nil {
		log.Fatalf("Failed reading SNP report: %v", err)
	}

	rawSNP := snpBuf.Bytes()
	fmt.Printf("SNP report size: %d bytes\n", len(rawSNP))

	// --------------------------------------------
	// 7. Save artifacts
	// --------------------------------------------
	os.WriteFile("tpm_quote.bin", quoteBlob.Bytes(), 0644)
	os.WriteFile("snp_report.bin", rawSNP, 0644)

	fmt.Println("Saved tpm_quote.bin and snp_report.bin")
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
// Helper: Create + Persist AK
// ------------------------------------------------------------
func createAndPersistAK(tpm transport.TPM, persistentHandle tpm2.TPMHandle) (tpm2.TPM2BName, error) {

	createRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgRSA,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				SignEncrypt:         true,
				Restricted:          true,
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgRSA,
				&tpm2.TPMSRSAParms{
					Scheme: tpm2.TPMTRSAScheme{
						Scheme: tpm2.TPMAlgRSASSA,
						Details: tpm2.NewTPMUAsymScheme(
							tpm2.TPMAlgRSASSA,
							&tpm2.TPMSSigSchemeRSASSA{
								HashAlg: tpm2.TPMAlgSHA256,
							},
						),
					},
					KeyBits: 2048,
				},
			),
		}),
	}.Execute(tpm)
	if err != nil {
		return tpm2.TPM2BName{}, fmt.Errorf("CreatePrimary failed: %v", err)
	}
	defer tpm2.FlushContext{FlushHandle: createRsp.ObjectHandle}.Execute(tpm)

	_, err = tpm2.EvictControl{
		Auth: tpm2.TPMRHOwner,
		ObjectHandle: &tpm2.NamedHandle{
			Handle: createRsp.ObjectHandle,
			Name:   createRsp.Name,
		},
		PersistentHandle: tpm2.TPMIDHPersistent(persistentHandle),
	}.Execute(tpm)
	if err != nil {
		return tpm2.TPM2BName{}, fmt.Errorf("EvictControl failed: %v", err)
	}

	// Read back the persisted key's name
	name, exists := readPersistentHandle(tpm, persistentHandle)
	if !exists {
		return tpm2.TPM2BName{}, fmt.Errorf("failed to read back persisted key")
	}
	return name, nil
}
