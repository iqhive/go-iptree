/*
 * IPTree Copyright 2016 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package iptree

import (
	"errors"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/iqhive/prefixlookup/preorder2"
	"github.com/iqhive/prefixlookup/routeid"
	"github.com/iqhive/prefixlookup/routeupdate"
)

var (
	ErrBadIP    = errors.New("Bad IP address or mask")
	ErrNotFound = errors.New("No Such Node")
	ErrNodeBusy = errors.New("Node Busy")
)

// IPTree is a longest-prefix-match index for IPv4 and IPv6 prefixes. Lookups
// are served from an immutable, lock-free preorder2 snapshot, while updates
// are applied through its dedicated writer goroutine.
type IPTree struct {
	mu      sync.RWMutex
	table   *preorder2.Table[any]
	catalog map[netip.Prefix]interface{}
	pending []routeupdate.Mutation[any]
	dirty   atomic.Bool
}

// New creates an empty IPTree.
func New() *IPTree {
	table, err := preorder2.New[any](nil, routeupdate.Options{})
	if err != nil {
		// Cannot happen with nil entries and default options.
		panic(err)
	}
	return &IPTree{
		table:   table,
		catalog: make(map[netip.Prefix]interface{}),
	}
}

// Close releases the internal writer goroutine. The tree must not be used
// after Close. It is safe to call more than once.
func (i *IPTree) Close() {
	i.table.Close()
}

func (i *IPTree) Add(cidr *net.IPNet, v interface{}) error {
	return i.AddByString(cidr.String(), v)
}

func (i *IPTree) AddByString(ipcidr string, v interface{}) error {
	prefix, err := parsePrefix(ipcidr)
	if err != nil {
		return err
	}
	return i.set(prefix, v, true)
}

func (i *IPTree) AddByNetIP(ipcidr net.IP, mask net.IPMask, v interface{}) error {
	prefix, err := netIPMaskToPrefix(ipcidr, mask)
	if err != nil {
		return err
	}
	return i.set(prefix, v, true)
}

func (i *IPTree) AddByNetIPAddr(ipcidr netip.Addr, mask netip.Prefix, v interface{}, overwrite bool) error {
	prefix, err := netIPAddrToPrefix(ipcidr, mask)
	if err != nil {
		return err
	}
	return i.set(prefix, v, overwrite)
}

func (i *IPTree) Get(ip net.IP) (interface{}, bool, error) {
	return i.GetByString(ip.String())
}

func (i *IPTree) GetByString(ipstr string) (interface{}, bool, error) {
	if p, err := netip.ParsePrefix(ipstr); err == nil {
		v, found := i.lookupLimited(p.Masked())
		return v, found, nil
	}
	if a, err := netip.ParseAddr(ipstr); err == nil {
		v, found := i.lookupFull(a)
		return v, found, nil
	}
	return nil, false, ErrBadIP
}

func (i *IPTree) GetIPNet(ip net.IPNet) (interface{}, bool, error) {
	prefix, err := netIPMaskToPrefix(ip.IP, ip.Mask)
	if err != nil {
		return nil, false, err
	}
	v, found := i.lookupLimited(prefix)
	return v, found, nil
}

func (i *IPTree) GetNetIP(ip net.IP) (interface{}, bool, error) {
	addr, err := netIPToAddr(ip)
	if err != nil {
		return nil, false, err
	}
	v, found := i.lookupFull(addr)
	return v, found, nil
}

func (i *IPTree) GetNetIPAddr(nip netip.Addr) (interface{}, bool, error) {
	if !nip.IsValid() || nip.Zone() != "" {
		return nil, false, ErrBadIP
	}
	v, found := i.lookupFull(nip)
	return v, found, nil
}

func (i *IPTree) DeleteByString(ipstr string) error {
	prefix, err := parsePrefix(ipstr)
	if err != nil {
		return err
	}
	return i.delete(prefix)
}

func (i *IPTree) DeleteByNetIP(ip net.IP, mask net.IPMask) error {
	prefix, err := netIPMaskToPrefix(ip, mask)
	if err != nil {
		return err
	}
	return i.delete(prefix)
}

func (i *IPTree) DeleteByNetIPAddr(nip netip.Addr, mask netip.Prefix) error {
	prefix, err := netIPAddrToPrefix(nip, mask)
	if err != nil {
		return err
	}
	return i.delete(prefix)
}

// AddBatch adds multiple CIDR entries to the tree at once.
func (i *IPTree) AddBatch(cidrs []string, v interface{}) error {
	for _, cidr := range cidrs {
		if err := i.AddByString(cidr, v); err != nil {
			return err
		}
	}
	return nil
}

// GetAll returns all entries in the IPTree as a map of CIDR strings to their values.
func (i *IPTree) GetAll() map[string]interface{} {
	result := make(map[string]interface{})
	i.mu.RLock()
	for prefix, value := range i.catalog {
		if value != nil {
			result[prefix.String()] = value
		}
	}
	i.mu.RUnlock()
	return result
}

// WalkV4Prefix iterates through all IPv4 entries in the IPTree, calling the
// provided function for each entry. If the callback returns an error,
// iteration stops and the error is returned.
func (i *IPTree) WalkV4Prefix(callback func(prefix netip.Prefix, value interface{}) error) error {
	return i.walkFamily(true, callback)
}

// WalkV4String iterates through all IPv4 entries in the IPTree, calling the
// provided function for each entry. If the callback returns an error,
// iteration stops and the error is returned.
func (i *IPTree) WalkV4String(callback func(prefix string, value interface{}) error) error {
	return i.walkFamily(true, func(prefix netip.Prefix, value interface{}) error {
		return callback(prefix.String(), value)
	})
}

// WalkV6Prefix iterates through all IPv6 entries in the IPTree, calling the
// provided function for each entry. If the callback returns an error,
// iteration stops and the error is returned.
func (i *IPTree) WalkV6Prefix(callback func(prefix netip.Prefix, value interface{}) error) error {
	return i.walkFamily(false, callback)
}

// WalkV6String iterates through all IPv6 entries in the IPTree, calling the
// provided function for each entry. If the callback returns an error,
// iteration stops and the error is returned.
func (i *IPTree) WalkV6String(callback func(prefix string, value interface{}) error) error {
	return i.walkFamily(false, func(prefix netip.Prefix, value interface{}) error {
		return callback(prefix.String(), value)
	})
}

// set inserts or replaces a prefix, honoring the overwrite flag.
func (i *IPTree) set(prefix netip.Prefix, v interface{}, overwrite bool) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if !overwrite && i.has(prefix) {
		return ErrNodeBusy
	}
	i.catalog[prefix] = v
	i.pending = append(i.pending, routeupdate.Mutation[any]{Prefix: prefix, Value: v})
	i.dirty.Store(true)
	return nil
}

// delete removes an exact prefix, preserving more-specific descendants.
func (i *IPTree) delete(prefix netip.Prefix) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.has(prefix) {
		return ErrNotFound
	}
	delete(i.catalog, prefix)
	i.pending = append(i.pending, routeupdate.Mutation[any]{Prefix: prefix, Delete: true})
	i.dirty.Store(true)
	return nil
}

// flush applies any pending mutations to the underlying preorder2 table as a
// single batch, so individual writes stay amortized O(1) instead of triggering
// a full snapshot rebuild each time.
func (i *IPTree) flush() {
	if !i.dirty.Load() {
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.dirty.Load() {
		return
	}
	// Mutations are validated before being queued, so this cannot fail in
	// normal operation. On failure the catalog remains authoritative for
	// iteration and existence checks.
	_ = i.table.ApplyBatch(i.pending)
	i.pending = nil
	i.dirty.Store(false)
}

// has reports whether a prefix holds a non-nil value.
func (i *IPTree) has(prefix netip.Prefix) bool {
	v, ok := i.catalog[prefix]
	return ok && v != nil
}

// lookupFull performs a full longest-prefix-match lookup.
func (i *IPTree) lookupFull(addr netip.Addr) (interface{}, bool) {
	i.flush()
	_, v, _ := i.table.Lookup(addr)
	if v != nil {
		return v, true
	}
	return v, false
}

// lookupLimited performs a longest-prefix-match lookup restricted to stored
// prefixes no longer than the given prefix.
func (i *IPTree) lookupLimited(prefix netip.Prefix) (interface{}, bool) {
	i.flush()
	ones := prefix.Bits()
	var result interface{}
	found := false
	i.table.WalkParents(prefix.Addr(), func(_ routeid.ID, p netip.Prefix, v any) bool {
		if v != nil && p.Bits() <= ones {
			result = v
			found = true
			return false
		}
		return true
	})
	return result, found
}

type prefixValue struct {
	prefix netip.Prefix
	value  interface{}
}

// walkFamily snapshots the catalog and invokes the callback for each entry of
// the requested address family, in a deterministic order.
func (i *IPTree) walkFamily(v4 bool, callback func(netip.Prefix, interface{}) error) error {
	i.mu.RLock()
	entries := make([]prefixValue, 0, len(i.catalog))
	for prefix, value := range i.catalog {
		if value != nil && prefix.Addr().Is4() == v4 {
			entries = append(entries, prefixValue{prefix, value})
		}
	}
	i.mu.RUnlock()

	sort.Slice(entries, func(a, b int) bool {
		return prefixLess(entries[a].prefix, entries[b].prefix)
	})

	for _, e := range entries {
		if err := callback(e.prefix, e.value); err != nil {
			return err
		}
	}
	return nil
}

func prefixLess(a, b netip.Prefix) bool {
	if a.Addr().Is4() != b.Addr().Is4() {
		return a.Addr().Is4()
	}
	if a.Addr() == b.Addr() {
		return a.Bits() < b.Bits()
	}
	return a.Addr().Less(b.Addr())
}

// parsePrefix parses a CIDR string or a bare address (interpreted as a host
// prefix). The returned prefix is canonical (host bits masked).
func parsePrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	return netip.Prefix{}, ErrBadIP
}

// netIPToAddr converts a net.IP to a netip.Addr.
func netIPToAddr(ip net.IP) (netip.Addr, error) {
	if ip4 := ip.To4(); ip4 != nil {
		a, ok := netip.AddrFromSlice(ip4)
		if !ok {
			return netip.Addr{}, ErrBadIP
		}
		return a, nil
	}
	if len(ip) != net.IPv6len {
		return netip.Addr{}, ErrBadIP
	}
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, ErrBadIP
	}
	return a, nil
}

// netIPMaskToPrefix converts a net.IP and net.IPMask to a canonical prefix.
func netIPMaskToPrefix(ip net.IP, mask net.IPMask) (netip.Prefix, error) {
	if ip4 := ip.To4(); ip4 != nil {
		ones, bits := mask.Size()
		switch bits {
		case 32:
			if ones < 0 {
				return netip.Prefix{}, ErrBadIP
			}
			a, ok := netip.AddrFromSlice(ip4)
			if !ok {
				return netip.Prefix{}, ErrBadIP
			}
			return netip.PrefixFrom(a, ones), nil
		case 128:
			if ones < 96 {
				return netip.Prefix{}, ErrBadIP
			}
			a, ok := netip.AddrFromSlice(ip4)
			if !ok {
				return netip.Prefix{}, ErrBadIP
			}
			return netip.PrefixFrom(a, ones-96), nil
		default:
			return netip.Prefix{}, ErrBadIP
		}
	}
	if len(ip) != net.IPv6len {
		return netip.Prefix{}, ErrBadIP
	}
	ones, bits := mask.Size()
	if bits != 128 || ones < 0 {
		return netip.Prefix{}, ErrBadIP
	}
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Prefix{}, ErrBadIP
	}
	return netip.PrefixFrom(a, ones), nil
}

// netIPAddrToPrefix validates an address and prefix pair and returns the
// canonical prefix formed from the address and the prefix's bit length.
func netIPAddrToPrefix(ip netip.Addr, mask netip.Prefix) (netip.Prefix, error) {
	if !ip.IsValid() || ip.Zone() != "" || !mask.IsValid() || mask.Addr().Zone() != "" {
		return netip.Prefix{}, ErrBadIP
	}
	if ip.Is4() != mask.Addr().Is4() {
		return netip.Prefix{}, ErrBadIP
	}
	return netip.PrefixFrom(ip, mask.Bits()).Masked(), nil
}
