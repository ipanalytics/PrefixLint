package prefixlint

import "net/netip"

type Severity int

const (
	SeverityInfo Severity = iota
	SeverityWarning
	SeverityError
	SeverityNone
)

type Finding struct {
	Rule     string   `json:"rule"`
	Severity string   `json:"severity"`
	Message  string   `json:"message"`
	File     string   `json:"file"`
	Line     int      `json:"line,omitempty"`
	Prefix   string   `json:"prefix,omitempty"`
	Related  []string `json:"related,omitempty"`
}

type Summary struct {
	InputRules          int    `json:"input_rules"`
	NormalizedRules     int    `json:"normalized_rules"`
	DuplicatePrefixes   int    `json:"duplicate_prefixes"`
	CoveredPrefixes     int    `json:"covered_prefixes"`
	AllowDenyConflicts  int    `json:"allow_deny_conflicts"`
	MalformedLines      int    `json:"malformed_lines"`
	CoverageUnchanged   bool   `json:"coverage_unchanged"`
	CompressionRatio    string `json:"compression_ratio"`
	NormalizedRulesText string `json:"normalized_rules_text,omitempty"`
}

type Report struct {
	Summary  Summary   `json:"summary"`
	Findings []Finding `json:"findings"`
}

func (r Report) Fails(threshold Severity) bool {
	if threshold == SeverityNone {
		return false
	}
	for _, finding := range r.Findings {
		if severityValue(finding.Severity) >= threshold {
			return true
		}
	}
	return false
}

type Entry struct {
	File      string
	Line      int
	Raw       string
	Comment   string
	Prefix    netip.Prefix
	Malformed bool
	Error     string
}

type CheckOptions struct {
	DenyPath   string
	AllowPath  string
	ConfigPath string
}
