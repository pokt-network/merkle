package merkle

import (
	"fmt"
	"github.com/pkg/profile"
	"testing"
)

const (
	numOfLeaves = 8
	index       = 1
)

var (
	data     [][]byte
	mockLeaf = []byte("bar")
)

func TestGenerateRoot(t *testing.T) {
	genData()
	defer profile.Start(profile.MemProfile).Stop()
	fmt.Println(GenerateRoot(data))
}

func TestGenerateProof(t *testing.T) {
	genData()
	defer profile.Start(profile.MemProfile).Stop()
	fmt.Println(GenerateProof(data, index))
}

func TestVerifyProof(t *testing.T) {
	genData()
	root := GenerateRoot(data)
	genData() // resets data
	proof := GenerateProof(data, index)
	p := profile.Start(profile.MemProfile)
	if !VerifyProof(root, mockLeaf, proof) {
		t.Fatalf("proof invalid")
	}
	p.Stop()
	if VerifyProof(root, []byte("foo"), proof) {
		t.Fatalf("proof invalid")
	}
}

func genData() {
	data = nil
	for i := 0; i < numOfLeaves; i++ {
		if i == index {
			data = append(data, mockLeaf)
			continue
		}
		data = append(data, []byte("foo"))
	}
}
