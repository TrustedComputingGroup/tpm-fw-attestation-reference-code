// Package main implements the entry logic for the tester tool.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/tcp"
	"github.com/trustedcomputinggroup/tpm-fw-attestation-reference-code/go/pkg/host"
	"github.com/trustedcomputinggroup/tpm-fw-attestation-reference-code/go/pkg/verifier"
)

var (
	tpmPort  = flag.Int("tpm_port", -1, "TPM port for running TCP TPM simulator")
	platPort = flag.Int("platform_port", -1, "Platform port for running TCP TPM simulator")
)

func main() {
	flag.Parse()

	if err := mainErr(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func getSimulator() (transport.TPMCloser, error) {
	if *tpmPort < 0 {
		return nil, errors.New("please provide --tpm_port")
	}
	if *platPort < 0 {
		return nil, errors.New("please provide --platform_port")
	}
	tpm, err := tcp.Open(tcp.Config{
		CommandAddress:  fmt.Sprintf("localhost:%d", *tpmPort),
		PlatformAddress: fmt.Sprintf("localhost:%d", *platPort),
	})

	if err != nil {
		return nil, err
	}

	err = tpm.PowerOn()
	if err != nil {
		return nil, fmt.Errorf("could not power on TPM: %w", err)
	}
	_, err = tpm2.Startup{
		StartupType: tpm2.TPMSUClear,
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("could not start up TPM: %w", err)
	}
	color.Green("Connected to TPM.")
	return tpm, nil
}

func mainErr() error {
	tpm, err := getSimulator()
	if err != nil {
		return fmt.Errorf("could not connect to TCP simulator: %w", err)
	}
	defer tpm.Close()

	h := host.NewHost(tpm)
	v := verifier.NewVerifier()

	ekPub, err := h.EKPub()
	if err != nil {
		return fmt.Errorf("could not fetch EK pub: %w", err)
	}

	challenge, err := v.CreateChallenge(&verifier.CreateChallengeReq{
		EKPub: ekPub,
	})
	if err != nil {
		return fmt.Errorf("could not create challenge: %w", err)
	}

	jsonChallenge, _ := json.MarshalIndent(challenge, "", "  ")
	color.Cyan("%s\n", string(jsonChallenge))

	solved, err := h.SolveChallenge(&host.SolveChallengeReq{
		Public:    challenge.Public,
		Duplicate: challenge.Duplicate,
		InSymSeed: challenge.InSymSeed,
	})
	if err != nil {
		return fmt.Errorf("could not solve challenge: %w", err)
	}

	jsonSolved, _ := json.MarshalIndent(solved, "", "  ")
	color.Cyan("%s\n", string(jsonSolved))

	finished, err := v.VerifyChallenge(&verifier.VerifyChallengeReq{
		AKPub:       solved.AKPub,
		CertifyInfo: solved.CertifyInfo,
		Signature:   solved.Signature,
	})
	if err != nil {
		return fmt.Errorf("could not verify challenge: %w", err)
	}

	jsonFinished, _ := json.MarshalIndent(finished, "", "  ")
	color.Cyan("%s\n", string(jsonFinished))

	color.Green("Success!\n")
	return nil
}
