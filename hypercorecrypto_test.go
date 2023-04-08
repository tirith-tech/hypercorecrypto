package hypercorecrypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

func TestKeyPairFromSeed(t *testing.T) {
	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	if err != nil {
		t.Fatalf("Error generating random seed: %v", err)
	}

	keyPair := KeyPairFromSeed(seed)

	if len(keyPair.PublicKey) != ed25519.PublicKeySize {
		t.Fatalf("Invalid public key length: got %v, want %v", len(keyPair.PublicKey), ed25519.PublicKeySize)
	}

	if len(keyPair.PrivateKey) != ed25519.PrivateKeySize {
		t.Fatalf("Invalid private key length: got %v, want %v", len(keyPair.PrivateKey), ed25519.PrivateKeySize)
	}
}

func TestNewKeyPair(t *testing.T) {
	keyPair := NewKeyPair()

	if len(keyPair.PublicKey) != ed25519.PublicKeySize {
		t.Fatalf("Invalid public key length: got %v, want %v", len(keyPair.PublicKey), ed25519.PublicKeySize)
	}

	if len(keyPair.PrivateKey) != ed25519.PrivateKeySize {
		t.Fatalf("Invalid private key length: got %v, want %v", len(keyPair.PrivateKey), ed25519.PrivateKeySize)
	}
}

func TestValidateKeyPair(t *testing.T) {
	keyPair := NewKeyPair()

	if !ValidateKeyPair(keyPair) {
		t.Fatal("Key pair validation failed")
	}
}

func TestSignVerify(t *testing.T) {
	keyPair := NewKeyPair()
	message := []byte("Hello, World!")
	signature := Sign(message, keyPair.PrivateKey)

	if !Verify(message, signature, keyPair.PublicKey) {
		t.Fatal("Signature verification failed")
	}

	// Test with an invalid signature
	invalidSignature := make([]byte, len(signature))
	copy(invalidSignature, signature)
	invalidSignature[0] ^= 0x01

	if Verify(message, invalidSignature, keyPair.PublicKey) {
		t.Fatal("Expected signature verification to fail with an invalid signature")
	}
}

func TestData(t *testing.T) {
	data := []byte("test data")
	hash1 := Data(data)
	hash2 := Data(data)

	if !bytes.Equal(hash1, hash2) {
		t.Fatal("Data hash function not deterministic")
	}
}

func TestParent(t *testing.T) {
	a := TreeNode{
		Index: 1,
		Hash:  []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0},
		Size:  100,
	}

	b := TreeNode{
		Index: 2,
		Hash:  []byte{0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12},
		Size:  200,
	}

	parent1 := Parent(a, b)
	parent2 := Parent(a, b)

	if !bytes.Equal(parent1, parent2) {
		t.Errorf("Expected parent hash: %x, got: %x", parent2, parent1)
	}
}

func TestTree(t *testing.T) {
	roots := []TreeNode{
		{
			Index: 0,
			Hash:  []byte{1, 2, 3, 4, 5, 6, 7, 8},
			Size:  32,
		},
		{
			Index: 1,
			Hash:  []byte{9, 10, 11, 12, 13, 14, 15, 16},
			Size:  64,
		},
	}

	expectedHash := []byte{242, 226, 9, 169, 94, 179, 197, 163, 227, 228, 62, 34, 147, 126, 101, 219, 254, 183, 92, 191, 104, 191, 181, 231, 74, 152, 232, 226, 227, 67, 234, 75}

	result := Tree(roots, nil)

	if !bytes.Equal(result, expectedHash) {
		t.Errorf("Tree function returned incorrect hash. Expected %v, got %v", expectedHash, result)
	}
}

func TestDiscoveryKey(t *testing.T) {
	keyPair := NewKeyPair()
	discoveryKey := DiscoveryKey(keyPair.PublicKey)

	if len(discoveryKey) != 32 {
		t.Fatalf("Invalid discovery key length: got %v, want 32", len(discoveryKey))
	}
}

func TestNamespace(t *testing.T) {
	name := []byte("testnamespace")
	count := 5
	ids := Namespace(name, count)

	if len(ids) != count {
		t.Fatalf("Invalid number of namespace ids: got %v, want %v", len(ids), count)
	}

	for i := 0; i < count; i++ {
		if len(ids[i]) != 32 {
			t.Fatalf("Invalid namespace id length at index %v: got %v, want 32", i, len(ids[i]))
		}
	}

	// Check for distinct namespace ids
	idsMap := make(map[string]bool)
	for i := 0; i < count; i++ {
		idStr := string(ids[i])
		if idsMap[idStr] {
			t.Fatalf("Duplicate namespace id found at index %v", i)
		}
		idsMap[idStr] = true
	}
}

func TestWriteUvarint(t *testing.T) {
	buf := &bytes.Buffer{}
	x := uint64(42)
	WriteUvarint(buf, x)

	// Read the value back and check if it's equal
	y, err := binary.ReadUvarint(buf)
	if err != nil {
		t.Fatalf("Error reading uvarint: %v", err)
	}

	if x != y {
		t.Fatalf("Written and read uvarint values do not match: got %v, want %v", y, x)
	}
}
