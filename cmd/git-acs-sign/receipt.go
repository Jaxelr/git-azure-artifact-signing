package main

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func transferReceipt(operation string, arguments []string) error {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return fmt.Errorf("load timestamp trust roots: %w", err)
	}
	return transferReceiptWithRoots(operation, arguments, roots)
}

func transferReceiptWithRoots(operation string, arguments []string, roots *x509.CertPool) error {
	if len(arguments) < 1 || len(arguments) > 2 {
		return fmt.Errorf("usage: git-acs-sign %s <receipt-path> [revision]", operation)
	}
	revision := "HEAD"
	if len(arguments) == 2 {
		revision = arguments[1]
	}
	signature, commitID, err := verifiedCommitSignature(revision)
	if err != nil {
		return err
	}
	source := ""
	if operation == "import-receipt" {
		source = arguments[0]
	}
	details, err := inspectSignatureFrom(signature, roots, source)
	if err != nil {
		return err
	}
	if details.timestamp == nil {
		return errors.New("receipt has no trusted timestamp to transfer")
	}
	destination := arguments[0]
	mode := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if operation == "import-receipt" {
		destination, err = localReceiptPath(signature)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			return fmt.Errorf("create certificate receipt directory: %w", err)
		}
		mode = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	data, err := json.MarshalIndent(details.receipt, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize certificate receipt: %w", err)
	}
	file, err := os.OpenFile(destination, mode, 0o600)
	if err != nil {
		return fmt.Errorf("open certificate receipt destination: %w", err)
	}
	_, writeErr := file.Write(append(data, '\n'))
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return fmt.Errorf("write certificate receipt: %w", err)
	}
	fmt.Printf("%s: %s\nCommit: %s\n", operation, destination, commitID)
	return nil
}
