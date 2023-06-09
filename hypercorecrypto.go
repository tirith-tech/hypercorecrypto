package hypercorecrypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"

	"github.com/minio/blake2b-simd"
	"golang.org/x/crypto/ed25519"
)

const (
	LeafType   = byte(0)
	ParentType = byte(1)
	RootType   = byte(2)
	Hypercore  = "hypercore"
)

type KeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
}

type TreeNode struct {
	Index uint64
	Hash  []byte
	Size  uint64
}

func KeyPairFromSeed(seed []byte) KeyPair {
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return KeyPair{PublicKey: publicKey, PrivateKey: privateKey}
}

func NewKeyPair() KeyPair {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	return KeyPair{PublicKey: publicKey, PrivateKey: privateKey}
}

func ValidateKeyPair(keyPair KeyPair) bool {
	return bytes.Equal(ed25519.PrivateKey(keyPair.PrivateKey).Public().(ed25519.PublicKey), keyPair.PublicKey)
}

func Sign(message, privateKey []byte) []byte {
	return ed25519.Sign(privateKey, message)
}

func Verify(message, signature, publicKey []byte) bool {
	return ed25519.Verify(publicKey, message, signature)
}

func Data(data []byte) []byte {
	hash := blake2b.New256()
	hash.Write([]byte{LeafType})
	WriteUvarint(hash, uint64(len(data)))
	hash.Write(data)
	return hash.Sum(nil)
}

func Parent(a, b TreeNode) []byte {
	if a.Index > b.Index {
		a, b = b, a
	}

	out := make([]byte, 32)

	parentType := []byte{ParentType}
	combinedSize := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(combinedSize, a.Size+b.Size)

	buffers := [][]byte{
		parentType,
		combinedSize[:n],
		a.Hash,
		b.Hash,
	}

	hash := blake2b.New256()
	for _, buf := range buffers {
		hash.Write(buf)
	}
	return hash.Sum(out[:0])
}

func Tree(roots []TreeNode, out []byte) []byte {
	hash := blake2b.New256()
	hash.Write([]byte{RootType})

	for _, r := range roots {
		hash.Write(r.Hash)
		writeUvarint(hash, r.Index)
		writeUvarint(hash, r.Size)
	}

	if out == nil {
		out = make([]byte, 32)
	}

	return hash.Sum(out[:0])
}

func writeUvarint(w io.Writer, x uint64) {
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], x)
	w.Write(buf[:n])
}

func RandomBytes(n int) []byte {
	buf := make([]byte, n)
	rand.Read(buf)
	return buf
}

func DiscoveryKey(publicKey []byte) []byte {
	hash := blake2b.New256()
	hash.Write([]byte(Hypercore))
	hash.Write(publicKey)
	return hash.Sum(nil)
}

func Namespace(name []byte, count int) [][]byte {
	ids := make([][]byte, count)
	buf := make([]byte, 32*count)
	ns := make([]byte, 33)
	hash := blake2b.New256()
	hash.Write(name)
	copy(ns, hash.Sum(nil))
	for i := range ids {
		ids[i] = buf[i*32 : (i+1)*32]
		ns[32] = byte(i)
		hash.Reset()
		hash.Write(ns)
		copy(ids[i], hash.Sum(nil))
	}
	return ids
}

func WriteUvarint(w io.Writer, x uint64) {
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], x)
	w.Write(buf[:n])
}
