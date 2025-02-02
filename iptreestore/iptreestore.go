package iptreestore

import (
	"bufio"
	"encoding/gob"
	"os"

	"github.com/iqhive/go-iptree/iptree"
)

// SaveIPTree serializes and saves an IPTree to a file efficiently using gob encoding
func SaveIPTreeToGob(tree *iptree.IPTree, filename string) error {
	// Create or truncate the file
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Use buffered writer for better performance
	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// Create gob encoder
	encoder := gob.NewEncoder(writer)

	// Create a map to store the tree data
	treeData := make(map[string]interface{})

	// Walk the tree and collect all IPv4 entries
	err = tree.WalkV4String(func(prefix string, value interface{}) error {
		treeData[prefix] = value
		return nil
	})
	if err != nil {
		return err
	}
	// Walk the tree and collect all IPv6 entries
	err = tree.WalkV6String(func(prefix string, value interface{}) error {
		treeData[prefix] = value
		return nil
	})
	if err != nil {
		return err
	}

	// Encode and write the tree data
	return encoder.Encode(treeData)
}

// LoadIPTree loads an IPTree from a file using gob decoding
func LoadIPTreeFromGob(filename string) (*iptree.IPTree, error) {
	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Use buffered reader for better performance
	reader := bufio.NewReader(file)

	// Create gob decoder
	decoder := gob.NewDecoder(reader)

	// Create map to decode into
	treeData := make(map[string]interface{})

	// Decode the tree data
	err = decoder.Decode(&treeData)
	if err != nil {
		return nil, err
	}

	// Create new tree
	tree := iptree.New()

	// Populate the tree
	for prefix, value := range treeData {
		err = tree.AddByString(prefix, value)
		if err != nil {
			return nil, err
		}
	}

	return tree, nil
}
