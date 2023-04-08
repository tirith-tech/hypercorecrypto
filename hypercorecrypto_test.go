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

func TestHashFunctions(t *testing.T) {
	data := []byte("Some data")
	hash1 := Data(data)
	hash2 := Data(data)

	if !bytes.Equal(hash1, hash2) {
		t.Fatal("Data hash function not deterministic")
	}

	left := []byte("left")
	right := []byte("right")
	parentHash := Parent(left, right, uint64(len(left)), uint64(len(right)))

	left2 := []byte("left2")
	right2 := []byte("right2")
	parentHash2 := Parent(left2, right2, uint64(len(left2)), uint64(len(right2)))

	if bytes.Equal(parentHash, parentHash2) {
		t.Fatal("Parent hash function not generating distinct hashes")
	}

	treeHash := Tree([][]byte{hash1, hash2}, nil)
	treeHash2 := Tree([][]byte{hash1, hash2}, nil)

	if !bytes.Equal(treeHash, treeHash2) {
		t.Fatal("Tree hash function not deterministic")
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
