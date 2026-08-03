package main

import (
	"strings"
	"testing"
	"time"
)

func sampleCertOutput(notAfter string) string {
	return "Certificate:\n" +
		"    Data:\n" +
		"        Version: 3 (0x2)\n" +
		"        Serial Number:\n" +
		"            00:00:00:00:00:00:00:00\n" +
		"        Signature Algorithm: sha256WithRSAEncryption\n" +
		"        Issuer: CN = Example CA\n" +
		"        Validity\n" +
		"            Not Before: Jan  1 00:00:00 2020 GMT\n" +
		"            Not After : " + notAfter + "\n" +
		"        Subject: CN = example.com\n" +
		"        Subject Public Key Info:\n" +
		"            Public Key Algorithm: rsaEncryption\n" +
		"                RSA Public-Key: (2048 bit)\n" +
		"        X509v3 extensions:\n" +
		"            X509v3 Subject Alternative Name:\n" +
		"                DNS:example.com, DNS:www.example.com\n"
}

func TestParseCertInfo(t *testing.T) {
	notAfter := "Aug  4 00:00:00 2026 GMT"
	r := strings.NewReader(sampleCertOutput(notAfter))
	opt := &Opt{}
	cert, err := opt.parseCertInfo(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cert.notAfter == nil {
		t.Fatal("notAfter is nil")
	}
	expectedTime, _ := time.Parse(layout, notAfter)
	if !cert.notAfter.Equal(expectedTime) {
		t.Fatalf("expected notAfter %v, got %v", expectedTime, cert.notAfter)
	}
	expectedSubjects := []string{"example.com", "www.example.com"}
	if len(cert.subjects) != len(expectedSubjects) {
		t.Fatalf("expected subjects %v, got %v", expectedSubjects, cert.subjects)
	}
	for i, s := range expectedSubjects {
		if cert.subjects[i] != s {
			t.Fatalf("expected subjects %v, got %v", expectedSubjects, cert.subjects)
		}
	}
}

func TestParseCertInfoSubjectCN(t *testing.T) {
	input := "Certificate:\n" +
		"    Data:\n" +
		"        Validity\n" +
		"            Not After : Aug  4 00:00:00 2026 GMT\n" +
		"        Subject CN = example.com\n"
	opt := &Opt{}
	cert, err := opt.parseCertInfo(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cert.subjects) != 1 || cert.subjects[0] != "example.com" {
		t.Fatalf("expected subjects [example.com], got %v", cert.subjects)
	}
}

func TestParseCertInfoMissingNotAfter(t *testing.T) {
	input := "Certificate:\n" +
		"    Data:\n" +
		"        Subject: CN = example.com\n"
	opt := &Opt{}
	_, err := opt.parseCertInfo(strings.NewReader(input))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "could not find notAfter") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseCertInfoInvalidNotAfter(t *testing.T) {
	input := "Certificate:\n" +
		"    Data:\n" +
		"        Validity\n" +
		"            Not After : invalid date\n"
	opt := &Opt{}
	_, err := opt.parseCertInfo(strings.NewReader(input))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "parsing time") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDaysRemaining(t *testing.T) {
	future := time.Now().UTC().Add(48 * time.Hour)
	cert := &certInfo{notAfter: &future}
	got := daysRemaining(cert)
	if got < 1 || got > 2 {
		t.Fatalf("expected 1 or 2, got %d", got)
	}
}

func TestVerifyServerNameDisabled(t *testing.T) {
	opt := &Opt{VerifyServerName: false}
	cert := &certInfo{subjects: []string{"example.com"}}
	if err := opt.verifyServerName(cert); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestVerifyServerNameExactMatch(t *testing.T) {
	opt := &Opt{VerifyServerName: true, ServerName: "example.com"}
	cert := &certInfo{subjects: []string{"example.com"}}
	if err := opt.verifyServerName(cert); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestVerifyServerNameWildcardMatch(t *testing.T) {
	opt := &Opt{VerifyServerName: true, ServerName: "www.example.com"}
	cert := &certInfo{subjects: []string{"*.example.com"}}
	if err := opt.verifyServerName(cert); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestVerifyServerNameMismatch(t *testing.T) {
	opt := &Opt{VerifyServerName: true, ServerName: "other.com"}
	cert := &certInfo{subjects: []string{"example.com"}}
	err := opt.verifyServerName(cert)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "is not included in") {
		t.Fatalf("unexpected error: %v", err)
	}
}
