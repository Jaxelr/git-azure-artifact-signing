package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/digitorus/timestamp"
	"github.com/jaxelr/artifact-signing-sdk-go/codesigning"
	"github.com/jaxelr/git-azure-artifact-signing/internal/config"
	"github.com/jaxelr/git-azure-artifact-signing/internal/sshsig"
	timestampverify "github.com/jaxelr/git-azure-artifact-signing/internal/timestamp"
)

type timestampRequester interface {
	Timestamp(context.Context, []byte, *codesigning.TimestampOptions) (*codesigning.TimestampResult, error)
}

func signArtifact(ctx context.Context, metadata config.Metadata, prepared sshsig.Prepared) (signingResult, error) {
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return signingResult{}, fmt.Errorf("create Azure credential: %w", err)
	}
	client, err := codesigning.NewCertificateProfileClient(metadata.Endpoint, credential, nil)
	if err != nil {
		return signingResult{}, fmt.Errorf("create Artifact Signing client: %w", err)
	}
	poller, err := client.BeginSign(ctx, metadata.CodeSigningAccountName, metadata.CertificateProfileName, codesigning.SignRequest{
		Digest:             prepared.Digest(),
		SignatureAlgorithm: to.Ptr(codesigning.SignatureAlgorithmRS256),
	}, nil)
	if err != nil {
		return signingResult{}, fmt.Errorf("start Artifact Signing operation: %w", err)
	}
	result, err := poller.PollUntilDone(ctx, nil)
	if err != nil {
		return signingResult{}, fmt.Errorf("complete Artifact Signing operation: %w", err)
	}
	return assembleSignature(prepared, result.Signature, result.SigningCertificate)
}
func timestampSignature(ctx context.Context, result signingResult, client timestampRequester, roots *x509.CertPool) (signingResult, error) {
	response, err := client.Timestamp(ctx, result.rawSignature, &codesigning.TimestampOptions{Hash: crypto.SHA256})
	if err != nil {
		return signingResult{}, fmt.Errorf("request ACS timestamp: %w", err)
	}
	if response == nil || len(response.RawToken) == 0 {
		return signingResult{}, errors.New("ACS returned an empty timestamp response")
	}
	if _, err := verifyTimestamp(response.RawToken, result.rawSignature, result.certificate, roots); err != nil {
		return signingResult{}, err
	}
	result.signature, err = sshsig.AttachTimestamp(result.signature, result.certificate.Raw, response.RawToken)
	if err != nil {
		return signingResult{}, fmt.Errorf("embed timestamp in SSH signature: %w", err)
	}
	return result, nil
}

func verifyTimestamp(response, signature []byte, certificate *x509.Certificate, roots *x509.CertPool) (*timestamp.Timestamp, error) {
	proof, err := timestampverify.Verify(response, signature, roots)
	if err != nil {
		return nil, err
	}
	if proof.Time.Before(certificate.NotBefore) || proof.Time.After(certificate.NotAfter) {
		return nil, errors.New("timestamp is outside the signing certificate's validity period")
	}
	return proof, nil
}
