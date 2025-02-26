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
	"net"
	"net/netip"

	"github.com/iqhive/nradix"
)

type IPTree struct {
	R *nradix.Tree
}

func ipToUint(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func New() *IPTree {
	t := new(IPTree)
	t.R = nradix.NewTree(0)
	return t
}

func (i *IPTree) Add(cidr *net.IPNet, v interface{}) error {
	return i.R.SetCIDRString(cidr.String(), v, true)
}

func (i *IPTree) AddByString(ipcidr string, v interface{}) error {
	return i.R.SetCIDRString(ipcidr, v, true)
}

func (i *IPTree) AddByNetIP(ipcidr net.IP, mask net.IPMask, v interface{}) error {
	return i.R.SetCIDRNetIP(ipcidr, mask, v, true)
}

func (i *IPTree) AddByNetIPAddr(ipcidr netip.Addr, mask netip.Prefix, v interface{}, overwrite bool) error {
	return i.R.SetCIDRNetIPAddr(ipcidr, mask, v, overwrite)
}

func (i *IPTree) Get(ip net.IP) (interface{}, bool, error) {
	v, err := i.R.FindCIDRString(ip.String())
	if v != nil {
		return v, true, err
	} else {
		return v, false, err
	}
}

func (i *IPTree) GetByString(ipstr string) (interface{}, bool, error) {
	v, err := i.R.FindCIDRString(ipstr)
	if v != nil {
		return v, true, err
	} else {
		return v, false, err
	}
}

func (i *IPTree) GetIPNet(ip net.IPNet) (interface{}, bool, error) {
	v, err := i.R.FindCIDRIPNet(ip)
	if v != nil {
		return v, true, err
	} else {
		return v, false, err
	}
}

func (i *IPTree) GetNetIP(ip net.IP) (interface{}, bool, error) {
	v, err := i.R.FindCIDRNetIP(ip)
	if v != nil {
		return v, true, err
	} else {
		return v, false, err
	}
}

func (i *IPTree) GetNetIPAddr(nip netip.Addr) (interface{}, bool, error) {
	v, err := i.R.FindCIDRNetIPAddr(nip)
	if v != nil {
		return v, true, err
	} else {
		return v, false, err
	}
}

func (i *IPTree) DeleteByString(ipstr string) error {
	return i.R.DeleteCIDRString(ipstr)
}

func (i *IPTree) DeleteByNetIP(ip net.IP, mask net.IPMask) error {
	return i.R.DeleteCIDRNetIP(ip, mask)
}

func (i *IPTree) DeleteByNetIPAddr(nip netip.Addr, mask netip.Prefix) error {
	return i.R.DeleteCIDRNetIPAddr(nip, mask)
}

// AddBatch adds multiple CIDR entries to the tree at once
func (i *IPTree) AddBatch(cidrs []string, v interface{}) error {
	for _, cidr := range cidrs {
		if err := i.AddByString(cidr, v); err != nil {
			return err
		}
	}
	return nil
}

// GetAll returns all entries in the IPTree as a map of CIDR strings to their values
func (i *IPTree) GetAll() map[string]interface{} {
	result := make(map[string]interface{})
	_ = i.WalkV4String(func(prefix string, value interface{}) error {
		result[prefix] = value
		return nil
	})
	_ = i.WalkV6String(func(prefix string, value interface{}) error {
		result[prefix] = value
		return nil
	})
	return result
}

// WalkV4Prefix iterates through all entries in the IPTree, calling the provided function
// for each entry. If the callback returns false, iteration stops.
func (i *IPTree) WalkV4Prefix(callback func(prefix netip.Prefix, value interface{}) error) error {
	return i.R.WalkV4(func(prefix netip.Prefix, value interface{}) error {
		if err := callback(prefix, value); err != nil {
			return err
		}
		return nil
	})
}

// WalkV4String iterates through all entries in the IPTree, calling the provided function
// for each entry. If the callback returns false, iteration stops.
func (i *IPTree) WalkV4String(callback func(prefix string, value interface{}) error) error {
	return i.R.WalkV4(func(prefix netip.Prefix, value interface{}) error {
		if err := callback(prefix.String(), value); err != nil {
			return err
		}
		return nil
	})
}

// WalkV6Prefix iterates through all entries in the IPTree, calling the provided function
// for each entry. If the callback returns false, iteration stops.
func (i *IPTree) WalkV6Prefix(callback func(prefix netip.Prefix, value interface{}) error) error {
	return i.R.WalkV6(func(prefix netip.Prefix, value interface{}) error {
		if err := callback(prefix, value); err != nil {
			return err
		}
		return nil
	})
}

// WalkV6String iterates through all entries in the IPTree, calling the provided function
// for each entry. If the callback returns false, iteration stops.
func (i *IPTree) WalkV6String(callback func(prefix string, value interface{}) error) error {
	return i.R.WalkV6(func(prefix netip.Prefix, value interface{}) error {
		if err := callback(prefix.String(), value); err != nil {
			return err
		}
		return nil
	})
}
