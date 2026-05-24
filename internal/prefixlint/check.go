package prefixlint

import "fmt"

func Check(opts CheckOptions) (Report, error) {
	cfg, err := LoadConfig(opts.ConfigPath)
	if err != nil {
		return Report{}, err
	}

	deny, err := ParseFile(opts.DenyPath)
	if err != nil {
		return Report{}, err
	}

	var findings []Finding
	for _, entry := range deny {
		if entry.Malformed {
			findings = append(findings, Finding{
				Rule:     "malformed",
				Severity: "error",
				Message:  entry.Error,
				File:     entry.File,
				Line:     entry.Line,
			})
		}
	}

	dupes := duplicateFindings(deny)
	findings = append(findings, dupes...)
	covered := coveredFindings(deny)
	findings = append(findings, covered...)
	private := privateFindings(deny)
	findings = append(findings, private...)

	conflicts := 0
	if opts.AllowPath != "" {
		allow, err := ParseFile(opts.AllowPath)
		if err != nil {
			return Report{}, err
		}
		conflictFindings := conflictFindings(NormalizeEntries(deny), NormalizeEntries(allow))
		conflicts = len(conflictFindings)
		findings = append(findings, conflictFindings...)
	}
	findings = applyConfig(findings, cfg)

	normalized := Normalize(deny)
	inputRules := len(usable(deny))
	summary := Summary{
		InputRules:         inputRules,
		NormalizedRules:    len(normalized),
		DuplicatePrefixes:  len(dupes),
		CoveredPrefixes:    len(covered),
		AllowDenyConflicts: conflicts,
		MalformedLines:     countMalformed(deny),
		CoverageUnchanged:  true,
		CompressionRatio:   formatCompression(inputRules, len(normalized)),
	}
	if inputRules > 0 {
		summary.NormalizedRulesText = fmt.Sprintf("%d rules -> %d rules, same coverage", inputRules, len(normalized))
	}

	return Report{Summary: summary, Findings: findings}, nil
}

func NormalizeEntries(entries []Entry) []Entry {
	byPrefix := map[string]Entry{}
	for _, entry := range usable(entries) {
		key := prefixKey(entry.Prefix)
		if _, ok := byPrefix[key]; !ok {
			byPrefix[key] = entry
		}
	}
	out := make([]Entry, 0, len(byPrefix))
	for _, entry := range byPrefix {
		out = append(out, entry)
	}
	sortEntries(out)
	return out
}

func duplicateFindings(entries []Entry) []Finding {
	seen := map[string]Entry{}
	var findings []Finding
	for _, entry := range entries {
		if entry.Malformed {
			continue
		}
		key := prefixKey(entry.Prefix)
		if first, ok := seen[key]; ok {
			findings = append(findings, Finding{
				Rule:     "duplicate",
				Severity: "warning",
				Message:  fmt.Sprintf("%s duplicates line %d", key, first.Line),
				File:     entry.File,
				Line:     entry.Line,
				Prefix:   key,
				Related:  []string{fmt.Sprintf("%s:%d", first.File, first.Line)},
			})
			continue
		}
		seen[key] = entry
	}
	return findings
}

func coveredFindings(entries []Entry) []Finding {
	candidates := usable(entries)
	sortEntries(candidates)
	var findings []Finding
	for i, entry := range candidates {
		for j := 0; j < i; j++ {
			parent := candidates[j]
			if prefixKey(parent.Prefix) == prefixKey(entry.Prefix) {
				continue
			}
			if covers(parent.Prefix, entry.Prefix) {
				findings = append(findings, Finding{
					Rule:     "covered",
					Severity: "warning",
					Message:  fmt.Sprintf("%s is fully covered by broader prefix %s on line %d", entry.Prefix, parent.Prefix, parent.Line),
					File:     entry.File,
					Line:     entry.Line,
					Prefix:   entry.Prefix.String(),
					Related:  []string{fmt.Sprintf("%s:%d", parent.File, parent.Line)},
				})
				break
			}
		}
	}
	return findings
}

func privateFindings(entries []Entry) []Finding {
	var findings []Finding
	for _, entry := range entries {
		if entry.Malformed {
			continue
		}
		addr := entry.Prefix.Addr()
		if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
			findings = append(findings, Finding{
				Rule:     "private-in-public-blocklist",
				Severity: "info",
				Message:  fmt.Sprintf("%s is non-public address space", entry.Prefix),
				File:     entry.File,
				Line:     entry.Line,
				Prefix:   entry.Prefix.String(),
			})
		}
	}
	return findings
}

func conflictFindings(deny, allow []Entry) []Finding {
	allowEntries := usable(allow)
	var findings []Finding
	for _, d := range usable(deny) {
		for _, a := range allowEntries {
			if covers(d.Prefix, a.Prefix) || covers(a.Prefix, d.Prefix) {
				findings = append(findings, Finding{
					Rule:     "allow-deny-conflict",
					Severity: "error",
					Message:  fmt.Sprintf("deny %s conflicts with allow %s on line %d", d.Prefix, a.Prefix, a.Line),
					File:     d.File,
					Line:     d.Line,
					Prefix:   d.Prefix.String(),
					Related:  []string{fmt.Sprintf("%s:%d", a.File, a.Line)},
				})
			}
		}
	}
	return findings
}

func countMalformed(entries []Entry) int {
	count := 0
	for _, entry := range entries {
		if entry.Malformed {
			count++
		}
	}
	return count
}
