package merkle

import (
	"bytes"
)

type Proof struct {
	Index  int
	Hashes [][]byte
}

// verifies the proof from the leaf node data, the merkle root, and the proof object
func VerifyProof(root, leaf []byte, proof Proof) bool {
	var res = Hash(leaf) // convert leaf to leafhash
	proofLen := len(proof.Hashes)
	for i := 0; i < proofLen; i++ {
		if proof.Index%2 == 1 { // odd index so hash to the left
			res = Hash(append(proof.Hashes[i], res...))
		} else { // even index so hash to the right
			res = Hash(append(res, proof.Hashes[i]...))
		}
		proof.Index /= 2
	}
	return bytes.Equal(root, res)
}

// generates the merkle proof object from the leaf node data and the index
func GenerateProof(data [][]byte, index int) Proof {
	// generate proof
	p := proof(structureLeaves(data), index, &Proof{})
	// reset index to leaf index
	p.Index = index
	return p
}

// generates the merkle root from leaf node data
func GenerateRoot(data [][]byte) []byte {
	return root(structureLeaves(data))
}

// dataLength must be > 1 or this breaks
func root(data [][]byte) []byte {
	data, atRoot := levelUp(data)
	if !atRoot {
		// if not at root continue to level up
		root(data)
	}
	// if at root return
	return data[0]
}

// recursive proof function that generates the proof object one level at a time
func proof(data [][]byte, index int, p *Proof) Proof {
	if index%2 == 1 { // odd index so add index - 1 to needed proof
		p.Hashes = append(p.Hashes, data[index-1])
	} else { // even index so add index + 1
		p.Hashes = append(p.Hashes, data[index+1])
	}
	data, atRoot := levelUp(data)
	if !atRoot {
		// next level Index = previous index / 2 (
		proof(data, index/2, p)
	} else {
		//p.Hashes = append(p.Hashes, data[0])
	}
	return *p
}

// takes the previous level data and converts it to the next level data
func levelUp(data [][]byte) (nextLevelData [][]byte, atRoot bool) {
	// then let's make our way to the top
	for i, d := range data {
		// if odd element, continue
		if i%2 == 1 {
			continue
		}
		// use the old data slice to add the next level data to
		data[i/2] = Hash(append(d, data[i+1]...))
	}
	// check to see if at root
	dataLen := len(data) / 2
	if dataLen == 1 {
		return data[:dataLen], true
	}
	return data[:dataLen], false
}

// takes normal data and structures them as a `balanced` merkle tree
func structureLeaves(data [][]byte) [][]byte {
	// first, let's hash the data
	for i, d := range data {
		data[i] = Hash(d)
	}
	// convert to proper tree len
	dataLen := len(data)
	properLength := nextPowerOfTwo(uint(dataLen))
	empty := make([][]byte, int(properLength)-dataLen)
	return append(data, empty...)
}

// computes the next power of 2
func nextPowerOfTwo(v uint) uint {
	v--
	v |= v >> 1
	v |= v >> 2
	v |= v >> 4
	v |= v >> 8
	v |= v >> 16
	v++
	return v
}
