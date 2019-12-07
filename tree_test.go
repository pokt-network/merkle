package merkle

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/wealdtech/go-merkletree/blake2b"
	"github.com/wealdtech/go-merkletree/keccak256"
)

// _byteArray is a helper to turn a string in to a byte array
func _byteArray(input string) []byte {
	x, _ := hex.DecodeString(input)
	return x
}

var tests = []struct {
	// hash type to use
	hashType HashType
	// data to create the node
	data [][]byte
	// expected error when attempting to create the tree
	createErr error
	// root hash after the tree has been created
	root []byte
	// salt to use
	salt []byte
	// saltedRoot hash after the tree has been created with the salt
	saltedRoot []byte
}{
	{ // 0
		hashType:  blake2b.New(),
		createErr: errors.New("tree must have at least 1 piece of data"),
	},
	{ // 1
		hashType:  blake2b.New(),
		data:      [][]byte{},
		createErr: errors.New("tree must have at least 1 piece of data"),
	},
	{ // 2
		hashType: blake2b.New(),
		data: [][]byte{
			[]byte("Foo"),
			[]byte("Bar"),
		},
		root:       _byteArray("e9e0083e456539e9f6336164cd98700e668178f98af147ef750eb90afcf2f637"),
		salt:       []byte("salt"),
		saltedRoot: _byteArray("420ba02ad7ce2077a2f82f4ac3752eeaf1285779a210391e9378337af0ed3539"),
	},
	{ // 3
		hashType: keccak256.New(),
		data: [][]byte{
			[]byte("Foo"),
			[]byte("Bar"),
		},
		root:       _byteArray("fb6c3a47aacb11c3f7ee3717cfbd43e4ad08da66d2cb049358db7e056baaaeed"),
		salt:       []byte("salt"),
		saltedRoot: _byteArray("5d3112070164037e104b3cc42ef5242e35616fdc6d2b34e3605154a3e5f9d594"),
	},
	{ // 4
		hashType: blake2b.New(),
		data: [][]byte{
			[]byte("Foo"),
		},
		root: _byteArray("7b506db718d5cce819ca4d33d2348065a5408cc89aa8b3f7ac70a0c186a2c81f"),
	},
	{ // 5
		hashType: blake2b.New(),
		data: [][]byte{
			[]byte("Foo"),
			[]byte("Bar"),
			[]byte("Baz"),
		},
		root: _byteArray("635ca493fe20a7b8485d2e4c650e33444664b4ce0773c36d2a9da79176f6889c"),
	},
	{ // 6
		hashType: blake2b.New(),
		data: [][]byte{
			[]byte("Foo"),
			[]byte("Bar"),
			[]byte("Baz"),
			[]byte("Qux"),
			[]byte("Quux"),
			[]byte("Quuz"),
		},
		root: _byteArray("4e6bdbaa326a760c45b5805898d7e9e788d65ffe7e27e690cd6999f1a5d64400"),
	},
	{ // 7
		hashType: blake2b.New(),
		data: [][]byte{
			[]byte("Foo"),
			[]byte("Bar"),
			[]byte("Baz"),
			[]byte("Qux"),
			[]byte("Quux"),
			[]byte("Quuz"),
			[]byte("FooBar"),
			[]byte("FooBaz"),
			[]byte("BarBaz"),
		},
		root: _byteArray("e15d86728d4a31c5880bc0d2d184637bb6672a72313af378141ea789f4b3929a"),
	},
}

func TestNew(t *testing.T) {
	for i, test := range tests {
		tree, err := NewUsing(test.data, test.hashType, nil)
		if test.createErr != nil {
			assert.Equal(t, test.createErr, err, fmt.Sprintf("expected error at test %d", i))
		} else {
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			assert.Equal(t, test.root, tree.Root(), fmt.Sprintf("unexpected root at test %d", i))
		}
	}
}

func TestProof(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil {
			tree, err := NewUsing(test.data, test.hashType, nil)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			for j, data := range test.data {
				proof, err := tree.GenerateProof(data)
				assert.Nil(t, err, fmt.Sprintf("failed to create proof at test %d data %d", i, j))
				proven, err := VerifyProofUsing(data, proof, tree.Root(), test.hashType, nil)
				assert.Nil(t, err, fmt.Sprintf("error verifying proof at test %d", i))
				assert.True(t, proven, fmt.Sprintf("failed to verify proof at test %d data %d", i, j))
			}
		}
	}
}

func TestSaltedProof(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil && test.salt != nil {
			tree, err := NewUsing(test.data, test.hashType, test.salt)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			assert.Equal(t, test.saltedRoot, tree.Root(), fmt.Sprintf("unexpected root at test %d", i))
			for j, data := range test.data {
				proof, err := tree.GenerateProof(data)
				assert.Nil(t, err, fmt.Sprintf("failed to create proof at test %d data %d", i, j))
				proven, err := VerifyProofUsing(data, proof, tree.Root(), test.hashType, test.salt)
				assert.Nil(t, err, fmt.Sprintf("error verifying proof at test %d", i))
				assert.True(t, proven, fmt.Sprintf("failed to verify proof at test %d data %d", i, j))
			}
		}
	}
}

func TestMissingProof(t *testing.T) {
	missingData := []byte("missing")
	for i, test := range tests {
		if test.createErr == nil {
			tree, err := NewUsing(test.data, test.hashType, nil)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			_, err = tree.GenerateProof(missingData)
			assert.Equal(t, err, errors.New("data not found"))
		}
	}

}

const _letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const _letterslen = len(_letters)

func _randomString(n int) string {
	res := make([]byte, n)
	for i := range res {
		res[i] = _letters[rand.Int63()%int64(_letterslen)]
	}
	return string(res)
}

func TestProofRandom(t *testing.T) {
	data := make([][]byte, 1000)
	for i := 0; i < 1000; i++ {
		data[i] = []byte(_randomString(6))
	}
	tree, err := New(data)
	assert.Nil(t, err, "failed to create tree")
	for i := range data {
		proof, err := tree.GenerateProof(data[i])
		assert.Nil(t, err, fmt.Sprintf("failed to create proof at data %d", i))
		proven, err := VerifyProof(data[i], proof, tree.Root())
		assert.True(t, proven, fmt.Sprintf("failed to verify proof at data %d", i))
	}
}

func TestString(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil {
			tree, err := NewUsing(test.data, test.hashType, nil)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			assert.Equal(t, fmt.Sprintf("%x", test.root), tree.String(), fmt.Sprintf("incorrect string representation at test %d", i))
		}
	}
}
