package merkle

import (
	"github.com/wealdtech/go-merkletree/blake2b"
)

func Hash(data []byte) []byte {
	return blake2b.New().Hash(data)
}
