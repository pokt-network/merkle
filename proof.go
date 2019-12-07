package merkle

import (
	"bytes"

	"github.com/wealdtech/go-merkletree/blake2b"
)

// Proof is a proof of a Merkle tree
type Proof struct {
	Hashes [][]byte
	Index  uint64
}

// newProof generates a Merkle proof
func newProof(hashes [][]byte, index uint64) *Proof {
	return &Proof{
		Hashes: hashes,
		Index:  index,
	}
}

// VerifyProof verifies a Merkle tree proof for a piece of data using the default hash type.
// The proof and path are as per Merkle tree's GenerateProof(), and root is the root hash of the tree against which the proof is to
// be verified.  Note that this does not require the Merkle tree to verify the proof, only its root; this allows for checking
// against historical trees without having to instantiate them.
//
// This returns true if the proof is verified, otherwise false.
func VerifyProof(data []byte, proof *Proof, root []byte) (bool, error) {
	return VerifyProofUsing(data, proof, root, blake2b.New(), nil)
}

// VerifyProofUsing verifies a Merkle tree proof for a piece of data using the provided hash type.
// The proof and path are as per Merkle tree's GenerateProof(), and root is the root hash of the tree against which the proof is to
// be verified.  Note that this does not require the Merkle tree to verify the proof, only its root; this allows for checking
// against historical trees without having to instantiate them.
//
// This returns true if the proof is verified, otherwise false.
func VerifyProofUsing(data []byte, proof *Proof, root []byte, hashType HashType, salt []byte) (bool, error) {
	var dataHash []byte
	if salt == nil {
		dataHash = hashType.Hash(data)
	} else {
		dataHash = hashType.Hash(append(data, salt...))
	}
	index := proof.Index + (1 << uint(len(proof.Hashes)))
	//	if index >= uint64(len(proof.Hashes)) {
	//		return false, errors.New("invalid proof")
	//	}

	for _, hash := range proof.Hashes {
		if index%2 == 0 {
			dataHash = hashType.Hash(append(dataHash, hash...))
		} else {
			dataHash = hashType.Hash(append(hash, dataHash...))
		}
		index = index >> 1
	}
	return bytes.Equal(dataHash, root), nil
}
