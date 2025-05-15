// Package e2etest implements integration tests for the protocol.
package e2etest

import (
	"encoding/json"
	"testing"

	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/trustedcomputinggroup/tpm-fw-attestation-reference-code/go/pkg/host"
	"github.com/trustedcomputinggroup/tpm-fw-attestation-reference-code/go/pkg/verifier"
)

func TestEndToEnd(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("OpenSimulator() = %v", err)
	}
	defer tpm.Close()

	h := host.NewHost(tpm)
	v := verifier.NewVerifier()

	ekPub, err := h.EKPub()
	if err != nil {
		t.Fatalf("EKPub() = %v", err)
	}

	challenge, err := v.CreateChallenge(&verifier.CreateChallengeReq{
		EKPub: ekPub,
	})
	if err != nil {
		t.Fatalf("CreateChallenge() = %v", err)
	}

	jsonChallenge, _ := json.MarshalIndent(challenge, "", "  ")
	t.Logf("%s\n", string(jsonChallenge))

	solved, err := h.SolveChallenge(&host.SolveChallengeReq{
		Public:    challenge.Public,
		Duplicate: challenge.Duplicate,
		InSymSeed: challenge.InSymSeed,
	})
	if err != nil {
		t.Fatalf("SolveChallenge() = %v", err)
	}

	jsonSolved, _ := json.MarshalIndent(solved, "", "  ")
	t.Logf("%s\n", string(jsonSolved))

	finished, err := v.VerifyChallenge(&verifier.VerifyChallengeReq{
		AKPub:       solved.AKPub,
		CertifyInfo: solved.CertifyInfo,
		Signature:   solved.Signature,
	})
	if err != nil {
		t.Fatalf("VerifyChallenge() = %v", err)
	}

	jsonFinished, _ := json.MarshalIndent(finished, "", "  ")
	t.Logf("%s\n", string(jsonFinished))
}
