package merkle

type HashFunc func([]byte) []byte

// HashType defines the interface that must be supplied by hash functions
type HashType interface {
	// Hash calculates the hash of a given input
	Hash([]byte) []byte
}
