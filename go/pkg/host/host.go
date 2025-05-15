// Package host implements the host logic for EK-Based Key Attestation with TPM Firmware Version.
package host

import (
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/trustedcomputinggroup/tpm-fw-attestation-reference-code/go/pkg/util"
)

type Host struct {
	tpm transport.TPMCloser
}

// NewHost creates a new Host.
func NewHost(tpm transport.TPMCloser) *Host {
	return &Host{
		tpm: tpm,
	}
}

// EKPub generates and returns the EK pub.
func (h *Host) EKPub() ([]byte, error) {
	cp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.ECCEKTemplate),
	}.Execute(h.tpm)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext{
		FlushHandle: cp.ObjectHandle,
	}.Execute(h.tpm)

	return cp.OutPublic.Bytes(), nil
}

type SolveChallengeReq struct {
	// The restricted HMAC key public area (TPM2B_PUBLIC contents)
	Public util.HexBytes
	// The wrapped restricted HMAC key sensitive area (TPM2B_PRIVATE contents)
	Duplicate util.HexBytes
	// The seed for the import of the restricted HMAC key under the EK (TPM2B_ENCRYPTED_SECRET contents)
	InSymSeed util.HexBytes
}

type SolveChallengeRsp struct {
	// The attested AK public area (TPM2B_PUBLIC contents)
	AKPub util.HexBytes
	// The attestation structure for Certify (TPM2B_ATTEST contents)
	CertifyInfo util.HexBytes
	// The signature over the attestation structure (TPM2B_SIGNATURE contents)
	Signature util.HexBytes
}

func (h *Host) SolveChallenge(req *SolveChallengeReq) (*SolveChallengeRsp, error) {
	// Generate the EK
	ek, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.ECCEKTemplate),
	}.Execute(h.tpm)
	if err != nil {
		return nil, fmt.Errorf("CreatePrimary() = %w", err)
	}
	defer tpm2.FlushContext{
		FlushHandle: ek.ObjectHandle,
	}.Execute(h.tpm)

	// Import the restricted HMAC key
	imported, err := tpm2.Import{
		ParentHandle: tpm2.AuthHandle{
			Handle: ek.ObjectHandle,
			Name:   ek.Name,
			Auth:   tpm2.Policy(tpm2.TPMAlgSHA256, 16, ekPolicy),
		},
		ObjectPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](req.Public),
		Duplicate:    tpm2.TPM2BPrivate{Buffer: req.Duplicate},
		InSymSeed:    tpm2.TPM2BEncryptedSecret{Buffer: req.InSymSeed},
	}.Execute(h.tpm)
	if err != nil {
		return nil, fmt.Errorf("Import() = %w", err)
	}

	// Load the imported HMAC key
	loaded, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: ek.ObjectHandle,
			Name:   ek.Name,
			Auth:   tpm2.Policy(tpm2.TPMAlgSHA256, 16, ekPolicy),
		},
		InPublic:  tpm2.BytesAs2B[tpm2.TPMTPublic](req.Public),
		InPrivate: imported.OutPrivate,
	}.Execute(h.tpm)
	if err != nil {
		return nil, fmt.Errorf("Load() = %w", err)
	}
	defer tpm2.FlushContext{
		FlushHandle: loaded.ObjectHandle,
	}.Execute(h.tpm)

	// TODO: certify a more interesting object
	// Certify the imported HMAC key using itself
	certified, err := tpm2.Certify{
		ObjectHandle: tpm2.NamedHandle{
			Handle: loaded.ObjectHandle,
			Name:   loaded.Name,
		},
		SignHandle: tpm2.NamedHandle{
			Handle: loaded.ObjectHandle,
			Name:   loaded.Name,
		},
	}.Execute(h.tpm)
	if err != nil {
		return nil, fmt.Errorf("Certify() = %w", err)
	}

	return &SolveChallengeRsp{
		// TODO: certify a more interesting object
		AKPub:       req.Public,
		CertifyInfo: certified.CertifyInfo.Bytes(),
		Signature:   tpm2.Marshal(certified.Signature),
	}, nil
}

func ekPolicy(t transport.TPM, handle tpm2.TPMISHPolicy, nonceTPM tpm2.TPM2BNonce) error {
	cmd := tpm2.PolicySecret{
		AuthHandle:    tpm2.TPMRHEndorsement,
		PolicySession: handle,
		NonceTPM:      nonceTPM,
	}
	_, err := cmd.Execute(t)
	return err
}
