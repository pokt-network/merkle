package merkle

import (
	"fmt"
	"github.com/pkg/profile"
	"testing"
)

const (
	numOfLeaves = 8
	index       = 0
)

var data [][]byte

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
	defer profile.Start(profile.MemProfile).Stop()
	if !VerifyProof(root, []byte("foo"), proof) {
		t.Fatalf("proof invalid")
	}
}

func genData() {
	data = nil
	for i := 0; i < numOfLeaves; i++ {
		data = append(data, []byte("foo"))
	}
}
