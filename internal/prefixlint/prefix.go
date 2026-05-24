package prefixlint

import (
	"math/big"
	"net/netip"
	"sort"
)

type rangePrefix struct {
	prefix netip.Prefix
	start  *big.Int
	end    *big.Int
	bits   int
}

func usable(entries []Entry) []Entry {
	out := make([]Entry, 0, len(entries))
	for _, entry := range entries {
		if !entry.Malformed {
			out = append(out, entry)
		}
	}
	return out
}

func sortEntries(entries []Entry) {
	sort.SliceStable(entries, func(i, j int) bool {
		a := entries[i].Prefix
		b := entries[j].Prefix
		if a.Addr().BitLen() != b.Addr().BitLen() {
			return a.Addr().BitLen() < b.Addr().BitLen()
		}
		cmp := addrInt(a.Addr()).Cmp(addrInt(b.Addr()))
		if cmp != 0 {
			return cmp < 0
		}
		return a.Bits() < b.Bits()
	})
}

func prefixRange(prefix netip.Prefix) rangePrefix {
	prefix = prefix.Masked()
	bits := prefix.Addr().BitLen()
	hostBits := bits - prefix.Bits()
	start := addrInt(prefix.Addr())
	size := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
	end := new(big.Int).Add(start, new(big.Int).Sub(size, big.NewInt(1)))
	return rangePrefix{prefix: prefix, start: start, end: end, bits: bits}
}

func covers(parent, child netip.Prefix) bool {
	if parent.Addr().BitLen() != child.Addr().BitLen() {
		return false
	}
	if parent.Bits() > child.Bits() {
		return false
	}
	return parent.Contains(child.Addr())
}

func addrInt(addr netip.Addr) *big.Int {
	bytes := addr.As16()
	if addr.Is4() {
		return new(big.Int).SetBytes(bytes[12:])
	}
	return new(big.Int).SetBytes(bytes[:])
}

func prefixKey(prefix netip.Prefix) string {
	return prefix.Masked().String()
}
