package auth

import (
	"testing"
)

const testHexKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestNewMFAEncryptor_Valid(t *testing.T) {
	enc, err := NewMFAEncryptor(testHexKey)
	if err != nil {
		t.Fatalf("NewMFAEncryptor: %v", err)
	}
	if enc == nil {
		t.Fatal("expected non-nil encryptor")
	}
}

func TestNewMFAEncryptor_InvalidHex(t *testing.T) {
	_, err := NewMFAEncryptor("not-hex")
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
}

func TestNewMFAEncryptor_WrongLength(t *testing.T) {
	_, err := NewMFAEncryptor("0123456789abcdef") // 8 bytes, not 32
	if err == nil {
		t.Fatal("expected error for wrong key length")
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	enc, err := NewMFAEncryptor(testHexKey)
	if err != nil {
		t.Fatalf("NewMFAEncryptor: %v", err)
	}

	plaintext := "JBSWY3DPEHPK3PXP"
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if ciphertext == plaintext {
		t.Fatal("ciphertext should not equal plaintext")
	}

	decrypted, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if decrypted != plaintext {
		t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestEncrypt_DifferentNonces(t *testing.T) {
	enc, err := NewMFAEncryptor(testHexKey)
	if err != nil {
		t.Fatalf("NewMFAEncryptor: %v", err)
	}

	plaintext := "JBSWY3DPEHPK3PXP"
	c1, _ := enc.Encrypt(plaintext)
	c2, _ := enc.Encrypt(plaintext)

	if c1 == c2 {
		t.Fatal("encrypting same plaintext twice should produce different ciphertexts (random nonces)")
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	enc1, _ := NewMFAEncryptor(testHexKey)
	enc2, _ := NewMFAEncryptor("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")

	ciphertext, _ := enc1.Encrypt("secret")
	_, err := enc2.Decrypt(ciphertext)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	enc, _ := NewMFAEncryptor(testHexKey)

	_, err := enc.Decrypt("not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}
