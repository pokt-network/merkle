package merkle

import (
	"bytes"
	"errors"
	"fmt"
	"math"

	"github.com/wealdtech/go-merkletree/blake2b"
)

// MerkleTree is the top-level structure for the merkle tree.
type Tree struct {
	// salt is the optional salt hashed with data to avoid rainbow attacks
	salt []byte
	// hash is a pointer to the hashing struct
	hash HashFunc
	// data is the data from which the Merkle tree is created
	data [][]byte
	// nodes are the leaf and branch nodes of the Merkle tree
	nodes [][]byte
}

func (t *Tree) indexOf(input []byte) (uint64, error) {
	for i, data := range t.data {
		if bytes.Compare(data, input) == 0 {
			return uint64(i), nil
		}

	}
	return 0, errors.New("data not found")
}

// GenerateProof generates the proof for a piece of data.
// If the data is not present in the tree this will return an error.
// If the data is present in the tree this will return the hashes for each level in the tree and details of if the hashes returned
// are the left-hand or right-hand hashes at each level (true if the left-hand, false if the right-hand).
func (t *Tree) GenerateProof(data []byte) (*Proof, error) {
	// Find the index of the data
	index, err := t.indexOf(data)
	if err != nil {
		return nil, err
	}

	proofLen := int(math.Ceil(math.Log2(float64(len(t.data)))))
	hashes := make([][]byte, proofLen)

	cur := 0
	for i := index + uint64(len(t.nodes)/2); i > 1; i /= 2 {
		hashes[cur] = t.nodes[i^1]
		cur++
	}
	return newProof(hashes, index), nil
}

// New creates a new Merkle tree using the provided raw data and default hash type.
// data must contain at least one element for it to be valid.
func New(data [][]byte) (*Tree, error) {
	return NewUsing(data, blake2b.New(), nil)
}

// NewUsing creates a new Merkle tree using the provided raw data and supplied hash type.
// data must contain at least one element for it to be valid.
func NewUsing(data [][]byte, hash HashType, salt []byte) (*Tree, error) {
	if len(data) == 0 {
		return nil, errors.New("tree must have at least 1 piece of data")
	}

	branchesLen := int(math.Exp2(math.Ceil(math.Log2(float64(len(data))))))

	// We pad our data length up to the power of 2
	nodes := make([][]byte, branchesLen+len(data)+(branchesLen-len(data)))
	// Leaves
	for i := range data {
		if salt == nil {
			nodes[i+branchesLen] = hash.Hash(data[i])
		} else {
			nodes[i+branchesLen] = hash.Hash(append(data[i], salt...))
		}
	}
	// Branches
	for i := branchesLen - 1; i > 0; i-- {
		nodes[i] = hash.Hash(append(nodes[i*2], nodes[i*2+1]...))
	}

	tree := &Tree{
		salt:  salt,
		hash:  hash.Hash,
		nodes: nodes,
		data:  data,
	}

	return tree, nil
}

// Root returns the Merkle root (hash of the root node) of the tree.
func (t *Tree) Root() []byte {
	return t.nodes[1]
}

// String implements the stringer interface
func (t *Tree) String() string {
	return fmt.Sprintf("%x", t.nodes[1])
}
