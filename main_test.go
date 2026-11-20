package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadConfigInputFromArgs(t *testing.T) {
	got, err := readConfigInput([]string{"vless://first", "trojan://second"}, "", strings.NewReader("ignored"))
	if err != nil || got != "vless://first\ntrojan://second" {
		t.Fatalf("got %q, err %v", got, err)
	}
}

func TestReadConfigInputFromStdin(t *testing.T) {
	got, err := readConfigInput(nil, "", strings.NewReader("trojan://test\n"))
	if err != nil || got != "trojan://test\n" {
		t.Fatalf("got %q, err %v", got, err)
	}
}

func TestReadConfigInputFromFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "links.txt")
	if err := os.WriteFile(file, []byte("vless://file"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readConfigInput(nil, file, strings.NewReader("ignored"))
	if err != nil || got != "vless://file" {
		t.Fatalf("got %q, err %v", got, err)
	}
}

func TestReadConfigInputRejectsAmbiguityAndOversize(t *testing.T) {
	if _, err := readConfigInput([]string{"vless://arg"}, "file.txt", strings.NewReader("")); err == nil {
		t.Fatal("expected error when both args and -file are set")
	}
	if _, err := readConfigInput(nil, "", strings.NewReader(strings.Repeat("x", maxInputBytes+1))); err == nil {
		t.Fatal("expected oversized input to fail")
	}
	if _, err := readConfigInput(nil, "", strings.NewReader("  \n")); err == nil {
		t.Fatal("expected empty input to fail")
	}
}
