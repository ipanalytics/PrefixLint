package prefixlint

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

func ParseFile(path string) ([]Entry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var entries []Entry
	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := scanner.Text()
		token, comment := splitLine(raw)
		if token == "" {
			continue
		}

		entry := Entry{File: path, Line: lineNo, Raw: raw, Comment: comment}
		prefix, err := parsePrefix(token)
		if err != nil {
			entry.Malformed = true
			entry.Error = err.Error()
		} else {
			entry.Prefix = prefix.Masked()
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func splitLine(raw string) (string, string) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", ""
	}
	if idx := strings.Index(line, "#"); idx >= 0 {
		return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:])
	}
	return line, ""
}

func parsePrefix(token string) (netip.Prefix, error) {
	if strings.Contains(token, "/") {
		prefix, err := netip.ParsePrefix(token)
		if err != nil {
			return netip.Prefix{}, err
		}
		return prefix, nil
	}
	addr, err := netip.ParseAddr(token)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid IP or CIDR prefix: %w", err)
	}
	if addr.Is4() {
		return netip.PrefixFrom(addr, 32), nil
	}
	return netip.PrefixFrom(addr, 128), nil
}
