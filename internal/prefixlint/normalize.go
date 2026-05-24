package prefixlint

import (
	"fmt"
	"math/big"
	"net/netip"
	"sort"
	"strings"
)

func Normalize(entries []Entry) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(entries))
	seen := map[string]bool{}
	for _, entry := range entries {
		if entry.Malformed {
			continue
		}
		key := prefixKey(entry.Prefix)
		if seen[key] {
			continue
		}
		seen[key] = true
		prefixes = append(prefixes, entry.Prefix.Masked())
	}
	sort.Slice(prefixes, func(i, j int) bool {
		a := prefixes[i]
		b := prefixes[j]
		if a.Addr().BitLen() != b.Addr().BitLen() {
			return a.Addr().BitLen() < b.Addr().BitLen()
		}
		cmp := addrInt(a.Addr()).Cmp(addrInt(b.Addr()))
		if cmp != 0 {
			return cmp < 0
		}
		return a.Bits() < b.Bits()
	})

	var kept []netip.Prefix
	for _, prefix := range prefixes {
		covered := false
		for _, existing := range kept {
			if covers(existing, prefix) {
				covered = true
				break
			}
		}
		if !covered {
			kept = append(kept, prefix)
		}
	}

	return collapseAdjacent(kept)
}

func FixFile(path string) (string, error) {
	entries, err := ParseFile(path)
	if err != nil {
		return "", err
	}
	normalized := Normalize(entries)
	lines := make([]string, 0, len(normalized))
	for _, prefix := range normalized {
		lines = append(lines, prefix.String())
	}
	if len(lines) == 0 {
		return "", nil
	}
	return strings.Join(lines, "\n") + "\n", nil
}

func collapseAdjacent(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) < 2 {
		return prefixes
	}
	changed := true
	for changed {
		changed = false
		sort.Slice(prefixes, func(i, j int) bool {
			a := prefixes[i]
			b := prefixes[j]
			if a.Addr().BitLen() != b.Addr().BitLen() {
				return a.Addr().BitLen() < b.Addr().BitLen()
			}
			cmp := addrInt(a.Addr()).Cmp(addrInt(b.Addr()))
			if cmp != 0 {
				return cmp < 0
			}
			return a.Bits() > b.Bits()
		})

		var next []netip.Prefix
		used := make([]bool, len(prefixes))
		for i := 0; i < len(prefixes); i++ {
			if used[i] {
				continue
			}
			merged := false
			for j := i + 1; j < len(prefixes); j++ {
				if used[j] {
					continue
				}
				if parent, ok := mergePair(prefixes[i], prefixes[j]); ok {
					next = append(next, parent)
					used[i] = true
					used[j] = true
					changed = true
					merged = true
					break
				}
			}
			if !merged && !used[i] {
				next = append(next, prefixes[i])
				used[i] = true
			}
		}
		prefixes = removeCovered(next)
	}
	sort.Slice(prefixes, func(i, j int) bool {
		a := prefixes[i]
		b := prefixes[j]
		if a.Addr().BitLen() != b.Addr().BitLen() {
			return a.Addr().BitLen() < b.Addr().BitLen()
		}
		return addrInt(a.Addr()).Cmp(addrInt(b.Addr())) < 0
	})
	return prefixes
}

func mergePair(a, b netip.Prefix) (netip.Prefix, bool) {
	a = a.Masked()
	b = b.Masked()
	if a.Addr().BitLen() != b.Addr().BitLen() || a.Bits() != b.Bits() || a.Bits() == 0 {
		return netip.Prefix{}, false
	}
	ra := prefixRange(a)
	rb := prefixRange(b)
	if new(big.Int).Add(ra.end, big.NewInt(1)).Cmp(rb.start) != 0 {
		return netip.Prefix{}, false
	}
	parentBits := a.Bits() - 1
	parent := netip.PrefixFrom(a.Addr(), parentBits).Masked()
	if covers(parent, a) && covers(parent, b) {
		return parent, true
	}
	return netip.Prefix{}, false
}

func removeCovered(prefixes []netip.Prefix) []netip.Prefix {
	sort.Slice(prefixes, func(i, j int) bool {
		a := prefixes[i]
		b := prefixes[j]
		if a.Addr().BitLen() != b.Addr().BitLen() {
			return a.Addr().BitLen() < b.Addr().BitLen()
		}
		cmp := addrInt(a.Addr()).Cmp(addrInt(b.Addr()))
		if cmp != 0 {
			return cmp < 0
		}
		return a.Bits() < b.Bits()
	})
	var out []netip.Prefix
	for _, prefix := range prefixes {
		covered := false
		for _, existing := range out {
			if covers(existing, prefix) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, prefix)
		}
	}
	return out
}

func formatCompression(input, normalized int) string {
	if input == 0 {
		return "0%"
	}
	saved := input - normalized
	return fmt.Sprintf("%.1f%% fewer rules", float64(saved)*100/float64(input))
}
