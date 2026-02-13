# Attestation Client

A Go binary that collects attestation evidence from an Azure Confidential VM (CVM), including a TPM Quote and the AMD SEV-SNP attestation report.

## How It Works

On Azure CVMs, the HCL (Host Compatibility Layer) firmware owns the interface to the AMD SEV-SNP hardware. You cannot call `/dev/sev-guest` or use ConfigFS TSM directly. Instead, the HCL pre-generates the SNP report at boot and stores it in vTPM NVRAM.

### What This Binary Does

1. Opens the TPM device (`/dev/tpmrm0`)
2. Reads the Azure-provisioned AIK (Attestation Identity Key) at persistent handle `0x81000003`
3. Reads the AIK certificate from NV index `0x01C101D0`
4. Generates a TPM Quote over PCRs 0,7 using the AIK
5. Reads the HCL report from NV index `0x01400001` (contains the SNP report)
6. Extracts the 1184-byte AMD SNP report (skipping the 32-byte HCL header)
7. Saves all artifacts to disk

### Output Files

| File | Contents |
|------|----------|
| `tpm_quote.bin` | Serialized TPM Quote (TPMS_ATTEST + TPMT_SIGNATURE) |
| `hcl_report.bin` | Full HCL report from NV index `0x01400001` |
| `snp_report.bin` | Extracted AMD SEV-SNP attestation report (1184 bytes) |
| `aik_cert.der` | AIK certificate in DER format |

## Azure CVM Attestation Architecture

### Key NV Indices

| NV Index | Name | Contents |
|----------|------|----------|
| `0x01400001` | `HCL_REPORT_INDEX` | SNP attestation report (32-byte header + 1184-byte report) |
| `0x01C101D0` | `AIK_CERT_INDEX` | AIK certificate (x.509 DER) |
| `0x81000003` | `AIK_PUB_INDEX` | AIK public key (persistent handle) |
| `0x81010001` | `EK_PUB_INDEX` | EK public key (persistent handle) |
| `0x01c00002` | `EK_CERT_INDEX` | EK certificate |

### Why Not `/dev/sev-guest` or ConfigFS TSM?

On Azure CVMs:

- **`/dev/sev-guest` doesn't exist** — the AMD PSP is not directly exposed to the guest OS
- **ConfigFS TSM has no backend** — no kernel module registers a provider because the HCL firmware owns the hardware
- **The SNP report is pre-baked at boot** into vTPM NVRAM, with `report_data` chosen by HCL (not the guest)
- **You cannot bind dynamic data** (like a TPM quote hash) into the SNP `report_data` field

The attestation binding works differently: the SNP report measures the HCL/vTPM firmware, and the TPM Quote (signed by the AIK) provides the runtime measurement chain. A verifier checks both independently.

### PCR Selection

The Azure attestation client library uses the following PCRs:

- **Linux:** PCRs 0, 1, 2, 3, 4, 5, 6, 7
- **Windows:** PCRs 0, 1, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14

| PCR | Measures |
|-----|----------|
| 0 | UEFI firmware code |
| 1 | UEFI firmware configuration |
| 2 | Option ROMs / additional firmware |
| 3 | Option ROM configuration |
| 4 | Boot loader (GRUB/shim) |
| 5 | Boot loader configuration / GPT partition table |
| 6 | Resume from S4/S5 (wake events) |
| 7 | Secure Boot policy (certificates, variables) |

## Secure Key Release (SKR) Flow

The SKR flow demonstrates how secrets can be securely released from Azure Key Vault to a verified CVM. The critical design: the ephemeral private key **never leaves the TPM**.

### Overview

```
┌─────────────┐     ┌─────────┐     ┌─────────────┐
│  Azure CVM  │     │   MAA   │     │  Azure KV   │
│  (with TPM) │     │         │     │  / mHSM     │
└──────┬──────┘     └────┬────┘     └──────┬──────┘
       │                 │                 │
       │ 1. Create ephemeral RSA key       │
       │    inside TPM (bound to PCRs)     │
       │                 │                 │
       │ 2. AIK certifies ephemeral key    │
       │    (proves key lives in TPM)      │
       │                 │                 │
       │ 3. Send evidence to MAA:          │
       │    - TPM Quote                    │
       │    - HCL/SNP report              │
       │    - AIK cert                     │
       │    - Certified ephemeral pub key  │
       ├────────────────►│                 │
       │                 │                 │
       │ 4. MAA validates everything,      │
       │    returns JWT with ephemeral     │
       │    pub key in x-ms-runtime.keys   │
       │◄────────────────┤                 │
       │                 │                 │
       │ 5. Send MAA JWT to AKV /release   │
       ├──────────────────────────────────►│
       │                 │                 │
       │ 6. AKV extracts ephemeral pub     │
       │    from JWT, wraps secret with it │
       │    using CKM_RSA_AES_KEY_WRAP     │
       │◄──────────────────────────────────┤
       │                 │                 │
       │ 7. Decrypt AES transfer key       │
       │    using TPM ephemeral priv key   │
       │                 │                 │
       │ 8. Unwrap actual secret           │
       │    with AES key (in memory)       │
       │                 │                 │
```

### Step-by-Step

| Step | What Happens | Where |
|------|-------------|-------|
| 1 | Create ephemeral RSA key pair bound to PCR values | **Inside TPM** (`Tss2Util::CreateEphemeralKey`) |
| 2 | AIK certifies the ephemeral key via `Esys_Certify()` | **Inside TPM** |
| 3 | Send TPM Quote + SNP report + certified ephemeral pub to MAA | **CVM → MAA** |
| 4 | MAA returns JWT with ephemeral pub in `x-ms-runtime.keys` | **MAA → CVM** |
| 5 | Send JWT as `target` to AKV `/release` endpoint | **CVM → AKV** |
| 6 | AKV wraps secret with ephemeral pub key from JWT | **AKV / mHSM** |
| 7 | Decrypt AES transfer key using TPM ephemeral private key | **Inside TPM** (`attestation_client->Decrypt`) |
| 8 | Unwrap actual secret with AES key | **In CVM memory** (`AES-256-wrap-pad`) |

### Security Guarantees

- The ephemeral private key **never leaves the TPM** — even if CVM memory is compromised after attestation, the wrapped response can only be decrypted by that specific TPM in that specific PCR state.
- AKV only releases the secret if the MAA token satisfies the key's release policy (e.g., `x-ms-attestation-type == sevsnpvm` and `x-ms-compliance-status == azure-compliant-cvm`).
- The CKM_RSA_AES_KEY_WRAP scheme: the first 256 bytes are the AES transfer key wrapped with the RSA ephemeral key, and the remaining bytes are the actual secret wrapped with that AES key.

### AKV Release Policy Example

```json
{
  "version": "1.0.0",
  "anyOf": [
    {
      "authority": "https://sharedweu.weu.attest.azure.net",
      "allOf": [
        {
          "claim": "x-ms-isolation-tee.x-ms-attestation-type",
          "equals": "sevsnpvm"
        },
        {
          "claim": "x-ms-isolation-tee.x-ms-compliance-status",
          "equals": "azure-compliant-cvm"
        }
      ]
    }
  ]
}
```

## Reference

- [Azure CVM Guest Attestation](https://github.com/Azure/confidential-computing-cvm-guest-attestation) — Microsoft's C++ attestation client library
- [go-tpm](https://github.com/google/go-tpm) — Google's Go TPM library (v0.9+)
- [AMD SEV-SNP whitepaper](https://www.amd.com/system/files/TechDocs/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf)
- [Microsoft Azure Attestation (MAA)](https://learn.microsoft.com/en-us/azure/attestation/overview)

## Build & Test

```bash
# Build
make attestation-cli

# Test on a CVM
./scripts/aks/test-attestation-cli.sh user@<cvm-ip>
```

## CLI equivalent (for reference)

```bash
# Read HCL report (SNP report) from vTPM NVRAM
tpm2_nvread -C o 0x01400001 > ./hcl_report.bin
dd skip=32 bs=1 count=1184 if=./hcl_report.bin of=./snp_report.bin

# Read AIK certificate
tpm2_nvread -C o 0x01C101D0 > ./aik_cert.der

# Generate TPM Quote with AIK
tpm2_quote -c 0x81000003 -l sha256:0,1,2,3,4,5,6,7 -m quote.bin -s sig.bin
```
