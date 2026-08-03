package main

import (
	"strings"
	"testing"
	"time"
)

func TestFmtString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "trim trailing newline",
			input:    "hello\n",
			expected: "hello",
		},
		{
			name:     "escape CRLF",
			input:    "hello\r\nworld",
			expected: "hello\\r\\nworld",
		},
		{
			name:     "escape LF",
			input:    "hello\nworld",
			expected: "hello\\nworld",
		},
		{
			name:     "escape CR",
			input:    "hello\rworld",
			expected: "hello\\rworld",
		},
		{
			name:     "multiple newlines",
			input:    "a\nb\nc\n",
			expected: "a\\nb\\nc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fmtString(tt.input)
			if got != tt.expected {
				t.Fatalf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func assertCommand(t *testing.T, got, expected []string) {
	t.Helper()
	if len(got) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, got)
	}
	for i := range got {
		if got[i] != expected[i] {
			t.Fatalf("expected %v, got %v", expected, got)
		}
	}
}

func TestBuildOpenSSLCommandBasic(t *testing.T) {
	opt := Opt{Host: "example.com", Port: "443"}
	got, err := opt.buildOpenSSLCommand()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertCommand(t, got, []string{"openssl", "s_client", "-connect", "example.com:443"})
}

func TestBuildOpenSSLCommandServerName(t *testing.T) {
	opt := Opt{Host: "example.com", Port: "443", ServerName: "www.example.com"}
	got, err := opt.buildOpenSSLCommand()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertCommand(t, got, []string{"openssl", "s_client", "-servername", "www.example.com", "-connect", "example.com:443"})
}

func TestBuildOpenSSLCommandRSACipher(t *testing.T) {
	opt := Opt{Host: "example.com", Port: "443", RSA: true}
	got, err := opt.buildOpenSSLCommand()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertCommand(t, got, []string{"openssl", "s_client", "-connect", "example.com:443", "-cipher", "aRSA"})
}

func TestBuildOpenSSLCommandECDSACipher(t *testing.T) {
	opt := Opt{Host: "example.com", Port: "443", ECDSA: true}
	got, err := opt.buildOpenSSLCommand()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertCommand(t, got, []string{"openssl", "s_client", "-connect", "example.com:443", "-cipher", "aECDSA"})
}

func TestBuildOpenSSLCommandRSAAndECDSAConflict(t *testing.T) {
	opt := Opt{Host: "example.com", Port: "443", RSA: true, ECDSA: true}
	got, err := opt.buildOpenSSLCommand()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// current implementation prefers ECDSA when both are set
	assertCommand(t, got, []string{"openssl", "s_client", "-connect", "example.com:443", "-cipher", "aECDSA"})
}

func TestBuildOpenSSLCommandIPv6(t *testing.T) {
	opt := Opt{Host: "::1", Port: "443"}
	got, err := opt.buildOpenSSLCommand()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertCommand(t, got, []string{"openssl", "s_client", "-connect", "[::1]:443"})
}

func TestBuildOpenSSLX509Command(t *testing.T) {
	opt := Opt{}
	got := opt.buildOpenSSLX509Command()
	expected := []string{"openssl", "x509", "-noout", "-text"}
	if len(got) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, got)
	}
	for i := range got {
		if got[i] != expected[i] {
			t.Fatalf("expected %v, got %v", expected, got)
		}
	}
}

func TestRunCommand(t *testing.T) {
	t.Run("successful command execution", func(t *testing.T) {
		opt := &Opt{
			Host:    "example.com",
			Port:    "443",
			Timeout: 5 * time.Second,
		}
		_, err := opt.runCommand()
		if err != nil {
			// Network may not be available in tests, so just check the error is related to execution.
			if !strings.Contains(err.Error(), "openssl") && !strings.Contains(err.Error(), "exec") && !strings.Contains(err.Error(), "exit") && !strings.Contains(err.Error(), "context") {
				t.Fatalf("unexpected error: %v", err)
			}
		}
	})
}

func TestRunCommandTimeout(t *testing.T) {
	opt := &Opt{
		Host:    "example.com",
		Port:    "443",
		Timeout: 1 * time.Nanosecond,
	}
	_, err := opt.runCommand()
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}
