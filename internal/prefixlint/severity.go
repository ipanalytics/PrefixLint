package prefixlint

import "fmt"

func ParseSeverityThreshold(value string) (Severity, error) {
	switch value {
	case "error":
		return SeverityError, nil
	case "warning":
		return SeverityWarning, nil
	case "info":
		return SeverityInfo, nil
	case "none":
		return SeverityNone, nil
	default:
		return SeverityNone, fmt.Errorf("unknown severity threshold %q", value)
	}
}

func severityValue(value string) Severity {
	switch value {
	case "error":
		return SeverityError
	case "warning":
		return SeverityWarning
	case "info":
		return SeverityInfo
	default:
		return SeverityInfo
	}
}
