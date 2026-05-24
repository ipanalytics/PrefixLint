package prefixlint

import (
	"encoding/json"
	"fmt"
	"strings"
)

func RenderReport(report Report, format string) (string, error) {
	switch format {
	case "text":
		return renderText(report), nil
	case "markdown":
		return renderMarkdown(report), nil
	case "json":
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return "", err
		}
		return string(data) + "\n", nil
	case "sarif":
		data, err := json.MarshalIndent(renderSARIF(report), "", "  ")
		if err != nil {
			return "", err
		}
		return string(data) + "\n", nil
	default:
		return "", fmt.Errorf("unknown report format %q", format)
	}
}

func renderText(report Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "prefixlint: %s\n", report.Summary.NormalizedRulesText)
	fmt.Fprintf(&b, "duplicates: %d, covered: %d, conflicts: %d, malformed: %d\n",
		report.Summary.DuplicatePrefixes,
		report.Summary.CoveredPrefixes,
		report.Summary.AllowDenyConflicts,
		report.Summary.MalformedLines,
	)
	for _, finding := range report.Findings {
		fmt.Fprintf(&b, "%s:%d: %s %s: %s\n", finding.File, finding.Line, finding.Severity, finding.Rule, finding.Message)
	}
	return b.String()
}

func renderMarkdown(report Report) string {
	var b strings.Builder
	b.WriteString("## PrefixLint report\n\n")
	fmt.Fprintf(&b, "**%s**\n\n", report.Summary.NormalizedRulesText)
	fmt.Fprintf(&b, "- Duplicate prefixes: `%d`\n", report.Summary.DuplicatePrefixes)
	fmt.Fprintf(&b, "- Prefixes covered by broader rules: `%d`\n", report.Summary.CoveredPrefixes)
	fmt.Fprintf(&b, "- Allow/deny conflicts: `%d`\n", report.Summary.AllowDenyConflicts)
	fmt.Fprintf(&b, "- Malformed lines: `%d`\n", report.Summary.MalformedLines)
	fmt.Fprintf(&b, "- Normalization impact: `%s`\n\n", report.Summary.CompressionRatio)
	if len(report.Findings) == 0 {
		b.WriteString("No findings.\n")
		return b.String()
	}
	b.WriteString("| Severity | Rule | Location | Message |\n")
	b.WriteString("| --- | --- | --- | --- |\n")
	for _, finding := range report.Findings {
		location := finding.File
		if finding.Line > 0 {
			location = fmt.Sprintf("%s:%d", finding.File, finding.Line)
		}
		fmt.Fprintf(&b, "| %s | `%s` | `%s` | %s |\n",
			finding.Severity,
			finding.Rule,
			location,
			escapeMarkdownTable(finding.Message),
		)
	}
	return b.String()
}

func escapeMarkdownTable(value string) string {
	return strings.ReplaceAll(value, "|", "\\|")
}

func renderSARIF(report Report) map[string]any {
	results := make([]map[string]any, 0, len(report.Findings))
	for _, finding := range report.Findings {
		level := "note"
		if finding.Severity == "error" {
			level = "error"
		} else if finding.Severity == "warning" {
			level = "warning"
		}
		results = append(results, map[string]any{
			"ruleId":  finding.Rule,
			"level":   level,
			"message": map[string]any{"text": finding.Message},
			"locations": []map[string]any{{
				"physicalLocation": map[string]any{
					"artifactLocation": map[string]any{"uri": finding.File},
					"region":           map[string]any{"startLine": max(1, finding.Line)},
				},
			}},
		})
	}
	return map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []map[string]any{{
			"tool": map[string]any{
				"driver": map[string]any{
					"name":           "PrefixLint",
					"informationUri": "https://github.com/ipanalytics/PrefixLint",
				},
			},
			"results": results,
		}},
	}
}
