package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
)

func loadSM2PublicKey(publicKey string) (*sm2.PublicKey, error) {
	bytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, err
	}
	return x509.ReadPublicKeyFromPem(bytes)
}

func loadSM2PrivateKey(privateKey string) (*sm2.PrivateKey, error) {
	bytes, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return nil, err
	}
	return x509.ReadPrivateKeyFromPem(bytes, nil)
}

func encryptSM2(publicKey *sm2.PublicKey, plainText []byte) ([]byte, error) {
	cipherText, err := sm2.Encrypt(publicKey, plainText, rand.Reader, sm2.C1C3C2)
	if err != nil {
		return nil, err
	}
	return cipherText, nil
}

func decryptSM2(privateKey *sm2.PrivateKey, ciphertext []byte) ([]byte, error) {
	plaintext, err := sm2.Decrypt(privateKey, ciphertext, sm2.C1C3C2)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
