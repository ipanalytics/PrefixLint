package prefixlint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckFindsDuplicatesCoveredMalformedAndConflicts(t *testing.T) {
	dir := t.TempDir()
	deny := filepath.Join(dir, "deny.txt")
	allow := filepath.Join(dir, "allow.txt")
	mustWrite(t, deny, "192.0.2.0/24\n192.0.2.1\n192.0.2.0/24\nbad\n10.0.0.0/8\n")
	mustWrite(t, allow, "192.0.2.128/25\n")

	report, err := Check(CheckOptions{DenyPath: deny, AllowPath: allow})
	if err != nil {
		t.Fatal(err)
	}

	if report.Summary.DuplicatePrefixes != 1 {
		t.Fatalf("duplicates = %d, want 1", report.Summary.DuplicatePrefixes)
	}
	if report.Summary.CoveredPrefixes != 1 {
		t.Fatalf("covered = %d, want 1", report.Summary.CoveredPrefixes)
	}
	if report.Summary.MalformedLines != 1 {
		t.Fatalf("malformed = %d, want 1", report.Summary.MalformedLines)
	}
	if report.Summary.AllowDenyConflicts != 1 {
		t.Fatalf("conflicts = %d, want 1", report.Summary.AllowDenyConflicts)
	}
}

func TestFixCollapsesCoverage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deny.txt")
	mustWrite(t, path, "203.0.113.0/25\n203.0.113.128/25\n203.0.113.1\n")

	fixed, err := FixFile(path)
	if err != nil {
		t.Fatal(err)
	}

	want := "203.0.113.0/24\n"
	if fixed != want {
		t.Fatalf("fixed = %q, want %q", fixed, want)
	}
}

func TestRenderMarkdown(t *testing.T) {
	report := Report{Summary: Summary{NormalizedRulesText: "2 rules -> 1 rules, same coverage", CompressionRatio: "50.0% fewer rules"}}
	out, err := RenderReport(report, "markdown")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "PrefixLint report") {
		t.Fatalf("markdown report missing title: %s", out)
	}
}

func TestConfigCanDisableRule(t *testing.T) {
	dir := t.TempDir()
	deny := filepath.Join(dir, "deny.txt")
	config := filepath.Join(dir, ".prefixlintrc.json")
	mustWrite(t, deny, "10.0.0.0/8\n")
	mustWrite(t, config, `{"rules":{"private-in-public-blocklist":"off"}}`)

	report, err := Check(CheckOptions{DenyPath: deny, ConfigPath: config})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(report.Findings))
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
