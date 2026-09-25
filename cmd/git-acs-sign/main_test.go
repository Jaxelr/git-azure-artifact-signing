package main

import (
	"strings"
	"testing"
)

func TestSigningInputPath(t *testing.T) {
	tests := []struct {
		name      string
		arguments []string
		want      string
	}{
		{
			name:      "Git temporary file",
			arguments: []string{"-Y", "sign", "-n", "git", "-f", `C:\repo\.git\artifact-signing\signing-key.pub`, "-q", `C:\Temp\git_signing_buffer`},
			want:      `C:\Temp\git_signing_buffer`,
		},
		{
			name:      "standard input",
			arguments: []string{"-Y", "sign", "-n", "git", "-f", "key.pub"},
			want:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := signingInputPath(tt.arguments); got != tt.want {
				t.Fatalf("signingInputPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractCommitSignature(t *testing.T) {
	rawCommit := strings.Join([]string{
		"tree abc",
		"gpgsig -----BEGIN SSH SIGNATURE-----",
		" payload",
		" -----END SSH SIGNATURE-----",
		"",
		"message",
	}, "\n")

	got, err := extractCommitSignature([]byte(rawCommit))
	if err != nil {
		t.Fatal(err)
	}
	want := "-----BEGIN SSH SIGNATURE-----\npayload\n-----END SSH SIGNATURE-----\n"
	if string(got) != want {
		t.Fatalf("extractCommitSignature() = %q, want %q", got, want)
	}
}

func TestExtractCommitSignatureRejectsUnsignedCommit(t *testing.T) {
	if _, err := extractCommitSignature([]byte("tree abc\n\nmessage\n")); err == nil {
		t.Fatal("extractCommitSignature() succeeded, want error")
	}
}
