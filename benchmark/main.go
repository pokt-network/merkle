package main

import (
	"fmt"
	"github.com/pokt-network/merkle"
	"github.com/pkg/profile"
	"unsafe"
)

func main() {
	Proof()
}

const (
	numOfLeaves = 100000000
	index       = 0
)

var data [][]byte

func init() {
	genData()
}

func Root() {
	defer profile.Start(profile.MemProfile).Stop()
	fmt.Println(cap(merkle.GenerateRoot(data)))
}

func Proof() {
	prof := profile.Start(profile.MemProfile)
	p := merkle.GenerateProof(data, index)
	prof.Stop()
	var size int
	for _, hash := range p.Hashes {
		size = size + cap(hash)
	}
	fmt.Println(unsafe.Sizeof(p.Index) + uintptr(size))
}

func Verify() {
	root := merkle.GenerateRoot(data)
	genData() // resets data
	proof := merkle.GenerateProof(data, index)
	defer profile.Start(profile.MemProfile).Stop()
	merkle.VerifyProof(root, []byte("foo"), proof)
}

func genData() {
	data = nil
	for i := 0; i < numOfLeaves; i++ {
		data = append(data, []byte("foo"))
	}
}
