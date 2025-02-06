/*
 * ZGrab Copyright 2016 Regents of the University of Michigan
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
	"net/netip"
	"testing"
)

func TestCreate(t *testing.T) {
	i := New()
	if i == nil {
		t.Error("new doesn't work")
	}
}

func TestExactValues(t *testing.T) {
	ip := New()
	ip.AddByString("1.2.3.4/32", 1)
	ip.AddByString("1.2.3.5/32", 2)
	if val, _, _ := ip.GetByString("1.2.3.4"); val.(int) != 1 {
		t.Error("Does not set exact value correctly.")
	}
	if val, _, _ := ip.GetByString("1.2.3.5"); val.(int) != 2 {
		t.Error("Does not set exact value correctly.")
	}
}

func TestDelete(t *testing.T) {
	ip := New()
	ip.AddByString("1.2.3.4/24", 1)
	ip.AddByString("1.2.3.5/32", 2)
	if val, _, _ := ip.GetByString("1.2.3.4"); val.(int) != 1 {
		t.Error("Does not set exact value correctly.")
	}
	if val, _, _ := ip.GetByString("1.2.3.5"); val.(int) != 2 {
		t.Error("Does not set exact value correctly.")
	}
	if err := ip.DeleteByString("1.2.3.4/24"); err != nil {
		t.Error(err)
	}
	if _, found, _ := ip.GetByString("1.2.3.4"); found {
		t.Error("Found deleted value.")
	}
	if val, _, _ := ip.GetByString("1.2.3.5"); val.(int) != 2 {
		t.Error("Does not set exact value correctly.")
	}
}

func TestCovering(t *testing.T) {
	ip := New()
	ip.AddByString("0.0.0.0/0", 1)
	if val, found, _ := ip.GetByString("1.2.3.4"); !found {
		t.Error("Values within covering value not found.")
	} else if val.(int) != 1 {
		t.Error("Value within covering set not correct")
	}
}

func TestMultiple(t *testing.T) {
	ip := New()
	ip.AddByString("0.0.0.0/0", 0)
	ip.AddByString("141.212.120.0/24", 3)
	if val, found, _ := ip.GetByString("1.2.3.4"); !found {
		t.Error("Values within covering value not found.")
	} else if val.(int) != 0 {
		t.Error("Value within covering set not correct")
	}
	if val, _, _ := ip.GetByString("141.212.120.15"); val.(int) != 3 {
		t.Error("Value within subset not correct")
	}
}

func TestFailingSubnet(t *testing.T) {
	ip := New()
	ip.AddByString("115.254.0.0/17", 3)
	ip.AddByString("115.254.0.0/22", 1)
	if val, _, _ := ip.GetByString("115.254.115.198"); val.(int) != 3 {
		t.Error("Value within subset not correct")
	}
	if val, _, _ := ip.GetByString("115.254.0.198"); val.(int) != 1 {
		t.Error("Value within subset not correct")
	}
}

func TestWalkV4String(t *testing.T) {
	ip := New()
	ip.AddByString("192.168.1.0/24", 1)
	ip.AddByString("10.0.0.0/8", 2)
	ip.AddByString("172.16.0.0/12", 3)
	ip.AddByString("2001:db8::/32", 4) // IPv6 address

	expectedCIDRs := map[string]int{
		"192.168.1.0/24": 1,
		"10.0.0.0/8":     2,
		"172.16.0.0/12":  3,
	}

	visitedCIDRs := make(map[string]int)

	err := ip.WalkV4String(func(prefix string, item interface{}) error {
		visitedCIDRs[prefix] = item.(int)
		return nil
	})

	if err != nil {
		t.Errorf("Walk failed: %v", err)
	}

	if len(visitedCIDRs) != len(expectedCIDRs) {
		t.Errorf("Expected %d CIDRs, got %d", len(expectedCIDRs), len(visitedCIDRs))
	}

	for cidr, value := range expectedCIDRs {
		if visitedCIDRs[cidr] != value {
			t.Errorf("For CIDR %s: expected value %d, got %d", cidr, value, visitedCIDRs[cidr])
		}
	}

	if _, found := visitedCIDRs["2001:db8::/32"]; found {
		t.Error("Unexpectedly found IPv6 CIDR in IPv4 walk")
	}
}

func TestWalkV4Prefix(t *testing.T) {
	ip := New()
	ip.AddByString("192.168.1.0/24", 1)
	ip.AddByString("10.0.0.0/8", 2)
	ip.AddByString("172.16.0.0/12", 3)
	ip.AddByString("2001:db8::/32", 4) // IPv6 address

	expectedCIDRs := map[string]int{
		"192.168.1.0/24": 1,
		"10.0.0.0/8":     2,
		"172.16.0.0/12":  3,
	}

	visitedCIDRs := make(map[string]int)

	err := ip.WalkV4Prefix(func(prefix netip.Prefix, item interface{}) error {
		visitedCIDRs[prefix.String()] = item.(int)
		return nil
	})

	if err != nil {
		t.Errorf("Walk failed: %v", err)
	}

	if len(visitedCIDRs) != len(expectedCIDRs) {
		t.Errorf("Expected %d CIDRs, got %d", len(expectedCIDRs), len(visitedCIDRs))
	}

	for cidr, value := range expectedCIDRs {
		if visitedCIDRs[cidr] != value {
			t.Errorf("For CIDR %s: expected value %d, got %d", cidr, value, visitedCIDRs[cidr])
		}
	}

	if _, found := visitedCIDRs["2001:db8::/32"]; found {
		t.Error("Unexpectedly found IPv6 CIDR in IPv4 walk")
	}
}

func TestWalkV6String(t *testing.T) {
	ip := New()
	ip.AddByString("2001:db8::/32", 1)
	ip.AddByString("2001:db8:1::/48", 2)
	ip.AddByString("2001:db8:2::/48", 3)
	ip.AddByString("192.168.1.0/24", 4) // IPv4 address

	expectedCIDRs := map[string]int{
		"2001:db8::/32":   1,
		"2001:db8:1::/48": 2,
		"2001:db8:2::/48": 3,
	}

	visitedCIDRs := make(map[string]int)

	err := ip.WalkV6String(func(prefix string, item interface{}) error {
		visitedCIDRs[prefix] = item.(int)
		return nil
	})

	if err != nil {
		t.Errorf("Walk failed: %v", err)
	}

	if len(visitedCIDRs) != len(expectedCIDRs) {
		t.Errorf("Expected %d CIDRs, got %d", len(expectedCIDRs), len(visitedCIDRs))
	}

	for cidr, value := range expectedCIDRs {
		if visitedCIDRs[cidr] != value {
			t.Errorf("For CIDR %s: expected value %d, got %d", cidr, value, visitedCIDRs[cidr])
		}
	}

	if _, found := visitedCIDRs["192.168.1.0/24"]; found {
		t.Error("Unexpectedly found IPv4 CIDR in IPv6 walk")
	}
}

func TestWalkV6Prefix(t *testing.T) {
	ip := New()
	ip.AddByString("2001:db8::/32", 1)
	ip.AddByString("2001:db8:1::/48", 2)
	ip.AddByString("2001:db8:2::/48", 3)
	ip.AddByString("192.168.1.0/24", 4) // IPv4 address

	expectedCIDRs := map[string]int{
		"2001:db8::/32":   1,
		"2001:db8:1::/48": 2,
		"2001:db8:2::/48": 3,
	}

	visitedCIDRs := make(map[string]int)

	err := ip.WalkV6Prefix(func(prefix netip.Prefix, item interface{}) error {
		visitedCIDRs[prefix.String()] = item.(int)
		return nil
	})

	if err != nil {
		t.Errorf("Walk failed: %v", err)
	}

	if len(visitedCIDRs) != len(expectedCIDRs) {
		t.Errorf("Expected %d CIDRs, got %d", len(expectedCIDRs), len(visitedCIDRs))
	}

	for cidr, value := range expectedCIDRs {
		if visitedCIDRs[cidr] != value {
			t.Errorf("For CIDR %s: expected value %d, got %d", cidr, value, visitedCIDRs[cidr])
		}
	}

	if _, found := visitedCIDRs["192.168.1.0/24"]; found {
		t.Error("Unexpectedly found IPv4 CIDR in IPv6 walk")
	}
}

func TestManualWalkV4Prefix(t *testing.T) {
	ip := New()
	ip.AddByString("0.0.0.0/0", 1)
	ip.AddByString("192.0.0.0/8", 2)
	ip.AddByString("192.168.0.0/16", 3)
	ip.AddByString("192.168.1.0/24", 4)

	node, value, err := ip.R.FindCIDRNetIPAddrWithNode(netip.MustParseAddr("192.168.0.1"))
	if err != nil {
		t.Errorf("Walk failed: %v", err)
	}
	if value != 3 {
		t.Errorf("Value for 192.168.0.1 is not correct (3)")
	}
	// if node != nil {
	// 	t.Logf("Node: %v, Prefix: %s, Value: %v", node, node.GetPrefix().String(), value)
	// }
	if node.GetPrefix().String() != "192.168.0.0/16" {
		t.Errorf("Node prefix search for 192.168.0.1 is not correct (192.168.0.0/16)")
	}
	if node.GetParent().GetPrefix().String() != "192.0.0.0/8" {
		t.Errorf("Parent prefix for 192.168.0.1 is not correct (192.0.0.0/8)")
	}
	parents := node.GetAllParents()
	if len(parents) != 2 {
		t.Errorf("Node has %d parents, expected 2", len(parents))
	}
	if parents[0].GetPrefix().String() != "192.0.0.0/8" {
		t.Errorf("1st Parent prefix for 192.168.0.1 (%s) is not correct (192.0.0.0/8)", parents[0].GetPrefix().String())
	}
	if parents[1].GetPrefix().String() != "0.0.0.0/0" {
		t.Errorf("2nd Parent prefix for 192.168.0.1 (%s) is not correct (0.0.0.0/0)", parents[1].GetPrefix().String())
	}

	node, value, err = ip.R.FindCIDRNetIPAddrWithNode(netip.MustParseAddr("192.168.1.1"))
	if err != nil {
		t.Errorf("Walk failed: %v", err)
	}
	// if node != nil {
	// 	t.Logf("Node: %v, Prefix: %s, Value: %v", node, node.GetPrefix().String(), value)
	// }
	if node.GetPrefix().String() != "192.168.1.0/24" {
		t.Errorf("Node prefix search for 192.168.1.1 is not correct (192.168.1.0/24)")
	}
	if node.GetParent().GetPrefix().String() != "192.168.0.0/16" {
		t.Errorf("Parent prefix for 192.168.1.1 is not correct (192.168.0.0/16)")
	}
	parents = node.GetAllParents()
	if len(parents) != 3 {
		t.Errorf("Node has %d parents, expected 2", len(parents))
	}
	if parents[0].GetPrefix().String() != "192.168.0.0/16" {
		t.Errorf("1st Parent prefix for 192.168.0.1 (%s) is not correct (192.168.0.0/16)", parents[0].GetPrefix().String())
	}
	if parents[1].GetPrefix().String() != "192.0.0.0/8" {
		t.Errorf("1st Parent prefix for 192.168.0.1 (%s) is not correct (192.0.0.0/8)", parents[0].GetPrefix().String())
	}
	if parents[2].GetPrefix().String() != "0.0.0.0/0" {
		t.Errorf("2nd Parent prefix for 192.168.0.1 (%s) is not correct (0.0.0.0/0)", parents[1].GetPrefix().String())
	}

	// if node.GetLeft() != nil {
	// 	t.Logf("Left: %v / %s", node.GetLeft(), node.GetLeft().GetIP())
	// }
	// if node.GetRight() != nil {
	// 	t.Logf("Right: %v / %s", node.GetRight(), node.GetRight().GetIP())
	// }
	t.Error("test")
}
