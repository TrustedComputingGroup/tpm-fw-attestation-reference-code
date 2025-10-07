// Package verifier implements verifier logic for EK-Based Key Attestation with TPM Firmware Version.
package verifier

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/trustedcomputinggroup/tpm-fw-attestation-reference-code/go/pkg/util"
)

var (
	ErrCertifiedWrongName = errors.New("incorrect name")
	ErrWrongHashAlg       = errors.New("wrong hash algorithm")
	ErrInvalidHMAC        = errors.New("invalid HMAC")
	ErrInvalidAttestation = errors.New("attestation statement was invalid")
)

type Verifier struct {
	mu sync.Mutex
	// The last HMAC key that was generated (CreateChallenge)
	hmacKey [32]byte
}

func NewVerifier() *Verifier {
	return &Verifier{}
}

type CreateChallengeReq struct {
	// The EK pub (TPM2B_PUBLIC contents)
	EKPub util.HexBytes
}

type CreateChallengeRsp struct {
	// The restricted HMAC key public area (TPM2B_PUBLIC contents)
	Public util.HexBytes
	// The wrapped restricted HMAC key sensitive area (TPM2B_PRIVATE contents)
	Duplicate util.HexBytes
	// The seed for the import of the restricted HMAC key under the EK (TPM2B_ENCRYPTED_SECRET contents)
	InSymSeed util.HexBytes
}

// CreateChallenge generates a new HMAC key and wraps it to the given EK.
// The Verifier will remember the HMAC key for VerifyChallenge later.
// Each time CreateChallenge is called, the HMAC key will be regenerated.
func (v *Verifier) CreateChallenge(req *CreateChallengeReq) (*CreateChallengeRsp, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	tPublic, err := tpm2.Unmarshal[tpm2.TPMTPublic](req.EKPub)
	if err != nil {
		return nil, err
	}

	encap, err := tpm2.ImportEncapsulationKey(tPublic)
	if err != nil {
		return nil, err
	}

	pub, sensitive := v.generateRestrictedHMACKey()
	name, err := tpm2.ObjectName(pub)
	if err != nil {
		return nil, err
	}

	duplicate, inSymSeed, err := tpm2.CreateDuplicate(rand.Reader, encap, name.Buffer, tpm2.Marshal(sensitive))
	if err != nil {
		return nil, err
	}

	return &CreateChallengeRsp{
		Public:    tpm2.Marshal(pub),
		Duplicate: duplicate,
		InSymSeed: inSymSeed,
	}, nil
}

type VerifyChallengeReq struct {
	// The attested AK public area (TPM2B_PUBLIC contents)
	AKPub util.HexBytes
	// The attestation structure for Certify (TPM2B_ATTEST contents)
	CertifyInfo util.HexBytes
	// The signature over the attestation structure (TPM2B_SIGNATURE contents)
	Signature util.HexBytes
}

type VerifyChallengeRsp struct {
	AttestedFirmwareVersion string
}

// VerifyChallenge checks the results of the attestation flow.
func (v *Verifier) VerifyChallenge(req *VerifyChallengeReq) (*VerifyChallengeRsp, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	akPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](req.AKPub)
	if err != nil {
		return nil, err
	}

	akName, err := tpm2.ObjectName(akPub)
	if err != nil {
		return nil, err
	}

	signature, err := tpm2.Unmarshal[tpm2.TPMTSignature](req.Signature)
	if err != nil {
		return nil, err
	}

	hmac, err := signature.Signature.HMAC()
	if err != nil {
		return nil, err
	}

	if err := v.verifyHMAC(req.CertifyInfo, hmac); err != nil {
		return nil, err
	}

	attest, err := tpm2.Unmarshal[tpm2.TPMSAttest](req.CertifyInfo)
	if err != nil {
		return nil, err
	}

	if err := verifyAttest(attest); err != nil {
		return nil, err
	}

	certify, err := attest.Attested.Certify()
	if err != nil {
		return nil, err
	}

	if err := verifyCertify(akName, certify); err != nil {
		return nil, err
	}

	return &VerifyChallengeRsp{
		AttestedFirmwareVersion: fmt.Sprintf("0x%0x", attest.FirmwareVersion),
	}, nil
}

// generateRestrictedHMACKey generates a new HMAC key, saves it to the Verifier's state, and emits the TPM public/private blobs.
func (v *Verifier) generateRestrictedHMACKey() (*tpm2.TPMTPublic, *tpm2.TPMTSensitive) {
	// Generate the random obfuscation value and key
	obfuscate := make([]byte, 32)
	rand.Read(obfuscate)
	rand.Read(v.hmacKey[:])

	// Unique for a KEYEDHASH object is H_nameAlg(obfuscate | key)
	// See Part 1, "Public Area Creation"
	h := sha256.New()
	h.Write(obfuscate)
	h.Write(v.hmacKey[:])

	pub := &tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			UserWithAuth: true,
			NoDA:         true,
			Restricted:   true,
			SignEncrypt:  true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
			Scheme: tpm2.TPMTKeyedHashScheme{
				Scheme: tpm2.TPMAlgHMAC,
				Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC, &tpm2.TPMSSchemeHMAC{
					HashAlg: tpm2.TPMAlgSHA256,
				}),
			},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgKeyedHash, &tpm2.TPM2BDigest{
			Buffer: h.Sum(nil),
		}),
	}

	priv := &tpm2.TPMTSensitive{
		SensitiveType: tpm2.TPMAlgKeyedHash,
		SeedValue: tpm2.TPM2BDigest{
			Buffer: obfuscate,
		},
		Sensitive: tpm2.NewTPMUSensitiveComposite(tpm2.TPMAlgKeyedHash, &tpm2.TPM2BSensitiveData{
			Buffer: v.hmacKey[:],
		}),
	}

	return pub, priv
}

// verifyHMAC checks the MAC on the given message.
func (v *Verifier) verifyHMAC(message []byte, ha *tpm2.TPMTHA) error {
	if ha.HashAlg != tpm2.TPMAlgSHA256 {
		return fmt.Errorf("%w %v (expected SHA256)", ErrWrongHashAlg, ha.HashAlg)
	}

	// The HMAC is over SHA256(message).
	digest := sha256.Sum256(message)

	h := hmac.New(sha256.New, v.hmacKey[:])
	h.Write(digest[:])
	if subtle.ConstantTimeCompare(ha.Digest, h.Sum(nil)) != 1 {
		return ErrInvalidHMAC
	}
	return nil
}

// verifyAttest checks that the attestation structure has valid data
func verifyAttest(attest *tpm2.TPMSAttest) error {
	if attest.Magic != tpm2.TPMGeneratedValue {
		return fmt.Errorf("%w: unexpected prefix %0x", ErrInvalidAttestation, attest.Magic)
	}

	if attest.Type != tpm2.TPMSTAttestCertify {
		return fmt.Errorf("%w: unexpected attestation type %0x", ErrInvalidAttestation, attest.Type)
	}

	// TODO: check qualified signer?

	return nil
}

// verifyCertify checks the certifyInfo against the given name.
func verifyCertify(name *tpm2.TPM2BName, certifyInfo *tpm2.TPMSCertifyInfo) error {
	// Check that the certified Name is the same as we expected.
	if !bytes.Equal(name.Buffer, certifyInfo.Name.Buffer) {
		return fmt.Errorf("%w: expected Name %x, certified Name was %x", ErrCertifiedWrongName, name.Buffer, certifyInfo.Name.Buffer)
	}

	// We can't really check the QualifiedName here, since we don't have any
	// information about the object's parent. As a paranoid consistency check,
	// just make sure that QualifiedName doesn't match Name for some reason.
	if bytes.Equal(certifyInfo.QualifiedName.Buffer, certifyInfo.Name.Buffer) {
		return fmt.Errorf("%w: QualifiedName unexpectedly matched Name", ErrCertifiedWrongName)
	}

	return nil
}
