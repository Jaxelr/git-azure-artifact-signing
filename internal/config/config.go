package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

type Metadata struct {
	Endpoint               string `json:"Endpoint"`
	CodeSigningAccountName string `json:"CodeSigningAccountName"`
	CertificateProfileName string `json:"CertificateProfileName"`
}

func Load(path string) (Metadata, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Metadata{}, fmt.Errorf("read metadata file %q: %w", path, err)
	}

	var metadata Metadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return Metadata{}, fmt.Errorf("parse metadata file %q: %w", path, err)
	}

	metadata.Endpoint = strings.TrimRight(strings.TrimSpace(metadata.Endpoint), "/")
	metadata.CodeSigningAccountName = strings.TrimSpace(metadata.CodeSigningAccountName)
	metadata.CertificateProfileName = strings.TrimSpace(metadata.CertificateProfileName)

	switch {
	case metadata.Endpoint == "":
		return Metadata{}, errors.New("metadata Endpoint is required")
	case metadata.CodeSigningAccountName == "":
		return Metadata{}, errors.New("metadata CodeSigningAccountName is required")
	case metadata.CertificateProfileName == "":
		return Metadata{}, errors.New("metadata CertificateProfileName is required")
	}

	endpoint, err := url.Parse(metadata.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" {
		return Metadata{}, errors.New("metadata Endpoint must be an absolute HTTPS URL")
	}

	return metadata, nil
}
