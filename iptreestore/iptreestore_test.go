package iptreestore

import (
	"testing"

	"github.com/iqhive/go-iptree/iptree"
)

type testCase struct {
	name    string
	cidrs   []string
	wantErr bool
}

func setupTestTree(t *testing.T, cidrs []string) *iptree.IPTree {
	t.Helper()
	tree := iptree.New()
	for _, cidr := range cidrs {
		err := tree.AddByString(cidr, cidr)
		if err != nil {
			t.Fatalf("failed to insert CIDR %s: %v", cidr, err)
		}
	}
	return tree
}

func verifyTreeContents(t *testing.T, tree *iptree.IPTree, cidrs []string) {
	t.Helper()
	for _, cidr := range cidrs {
		_, exists, err := tree.GetByString(cidr)
		if err != nil {
			t.Errorf("error checking CIDR %s: %v", cidr, err)
		}
		if !exists {
			t.Errorf("CIDR %s not found in tree", cidr)
		}
	}
}

func TestIPTreeStorage(t *testing.T) {
	tests := []testCase{
		{
			name:    "basic_cidrs",
			cidrs:   []string{"192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"},
			wantErr: false,
		},
		{
			name:    "empty_tree",
			cidrs:   []string{},
			wantErr: false,
		},
		{
			name:    "single_cidr",
			cidrs:   []string{"192.168.1.0/24"},
			wantErr: false,
		},
		{
			name:    "ipv6_cidrs",
			cidrs:   []string{"2001:db8::/32", "fe80::/10"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create and populate original tree
			originalTree := setupTestTree(t, tt.cidrs)

			// Test Save
			tempFile := t.TempDir() + "/" + tt.name + ".gob"
			err := SaveIPTreeToGob(originalTree, tempFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("SaveIPTreeToGob() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Test Load
			loadedTree, err := LoadIPTreeFromGob(tempFile)
			if err != nil {
				t.Fatalf("LoadIPTreeFromGob() error = %v", err)
			}

			// Verify contents
			verifyTreeContents(t, loadedTree, tt.cidrs)
		})
	}
}
