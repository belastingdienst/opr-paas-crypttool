/*
Copyright 2026, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

const (
	// AlgorithmRSAOAEP identifies the legacy scheme: RSA-OAEP applied directly, blockwise, to the
	// secret (see EncryptRsa/DecryptRsa in crypt.go and private_keys.go).
	AlgorithmRSAOAEP = "RSA-OAEP"

	// AlgorithmMLKEM768 identifies the post-quantum hybrid scheme implemented in this file: an
	// ML-KEM-768 (FIPS 203) key encapsulation establishes a shared secret, which HKDF-SHA256 expands
	// into an AES-256 key used to AES-256-GCM-seal the actual secret. ML-KEM-768 and AES-256-GCM are
	// both NIST-standardized primitives; no custom cryptographic primitive is introduced here, only
	// their standard hybrid-encryption composition.
	AlgorithmMLKEM768 = "ML-KEM-768+AES-256-GCM"

	mlkemPrivateKeyPEMType = "ML-KEM-768 PRIVATE KEY"
	mlkemPublicKeyPEMType  = "ML-KEM-768 PUBLIC KEY"

	// hybridMagic tags a ciphertext produced by hybridEncrypt so Crypt.Decrypt can tell it apart from a
	// legacy raw RSA-OAEP ciphertext, which carries no header of its own.
	hybridMagic        = "PQH1"
	hybridGCMNonceSize = 12
	hybridAESKeySize   = 32
)

// isHybridCiphertext reports whether raw was produced by hybridEncrypt.
func isHybridCiphertext(raw []byte) bool {
	return len(raw) > len(hybridMagic) && string(raw[:len(hybridMagic)]) == hybridMagic
}

// hybridEncrypt encapsulates a fresh shared secret to pub, expands it (bound to encryptionContext) into
// an AES-256 key via HKDF-SHA256, and uses that key to AES-256-GCM-seal secret. The returned bytes are
// self-describing (magic || kemCiphertext || nonce || sealed) so hybridDecrypt needs no extra state.
func hybridEncrypt(pub *mlkem768.PublicKey, secret []byte, encryptionContext []byte) ([]byte, error) {
	kemCiphertext := make([]byte, mlkem768.CiphertextSize)
	sharedSecret := make([]byte, mlkem768.SharedKeySize)
	pub.EncapsulateTo(kemCiphertext, sharedSecret, nil)

	gcm, err := newHybridAEAD(sharedSecret, encryptionContext)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	sealed := gcm.Seal(nil, nonce, secret, nil)

	out := make([]byte, 0, len(hybridMagic)+len(kemCiphertext)+len(nonce)+len(sealed))
	out = append(out, []byte(hybridMagic)...)
	out = append(out, kemCiphertext...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

// hybridDecrypt reverses hybridEncrypt using priv. It returns an error if raw is malformed, was
// encrypted for a different key, or was encrypted under a different encryptionContext.
func hybridDecrypt(priv *mlkem768.PrivateKey, raw []byte, encryptionContext []byte) ([]byte, error) {
	if !isHybridCiphertext(raw) {
		return nil, errors.New("not a hybrid ciphertext")
	}
	rest := raw[len(hybridMagic):]
	if len(rest) < mlkem768.CiphertextSize+hybridGCMNonceSize {
		return nil, errors.New("hybrid ciphertext truncated")
	}
	kemCiphertext := rest[:mlkem768.CiphertextSize]
	rest = rest[mlkem768.CiphertextSize:]
	nonce := rest[:hybridGCMNonceSize]
	sealed := rest[hybridGCMNonceSize:]

	sharedSecret := make([]byte, mlkem768.SharedKeySize)
	priv.DecapsulateTo(sharedSecret, kemCiphertext)

	gcm, err := newHybridAEAD(sharedSecret, encryptionContext)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nonce, sealed, nil)
}

// newHybridAEAD derives an AES-256 key from an ML-KEM-768 shared secret via HKDF-SHA256 (RFC 5869),
// binding encryptionContext as the HKDF 'info' the same way EncryptRsa/DecryptRsa bind it as an
// RSA-OAEP label, and wraps it in AES-256-GCM.
func newHybridAEAD(sharedSecret []byte, encryptionContext []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, sharedSecret, nil, string(encryptionContext), hybridAESKeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to derive AES key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to init AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to init AES-GCM: %w", err)
	}
	return gcm, nil
}
