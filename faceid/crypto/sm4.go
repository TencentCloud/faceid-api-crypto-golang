package crypto

import (
	"crypto/cipher"
	"github.com/tjfoc/gmsm/sm4"
)

func encryptSM4GCM(key, plaintext, iv []byte) ([]byte, []byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	ciphertext := gcm.Seal(nil, iv, plaintext, nil)
	tag := ciphertext[len(ciphertext)-gcm.Overhead():]
	ciphertextWithoutTag := ciphertext[:len(ciphertext)-gcm.Overhead()]
	return ciphertextWithoutTag, tag, nil

}

func decryptSM4GCM(key, ciphertext, iv, tag []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertextWithTag := append(ciphertext, tag...)
	plaintext, err := gcm.Open(nil, iv, ciphertextWithTag, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
