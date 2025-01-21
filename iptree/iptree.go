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
	"fmt"
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
	return i.R.AddCIDRString(cidr.String(), v)
}

func (i *IPTree) AddByString(ipcidr string, v interface{}) error {
	return i.R.AddCIDRString(ipcidr, v)
}

func (i *IPTree) AddByNetIP(ipcidr net.IP, mask net.IPMask, v interface{}) error {
	return i.R.AddCIDRNetIP(ipcidr, mask, v)
}

func (i *IPTree) AddByNetIPAddr(ipcidr netip.Addr, mask netip.Prefix, v interface{}) error {
	return i.R.AddCIDRNetIPAddr(ipcidr, mask, v)
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

// GetAll returns all entries in the IPTree as a map of CIDR strings to their values
func (i *IPTree) GetAll() map[string]interface{} {
	result := make(map[string]interface{})
	_ = i.R.Walk(func(prefix string, value interface{}) error {
		result[prefix] = value
		return nil
	})
	return result
}

// Walk iterates through all entries in the IPTree, calling the provided function
// for each entry. If the callback returns false, iteration stops.
func (i *IPTree) Walk(callback func(prefix string, value interface{}) bool) error {
	return i.R.Walk(func(prefix string, value interface{}) error {
		if !callback(prefix, value) {
			return fmt.Errorf("walk stopped")
		}
		return nil
	})
}
