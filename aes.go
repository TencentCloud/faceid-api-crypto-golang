package faceid

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

func encryptAES256CBC(key, plaintext, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	pkcs7 := func(cipherText []byte, blockSize int) []byte {
		padding := blockSize - len(cipherText)%blockSize
		padText := bytes.Repeat([]byte{byte(padding)}, padding)
		return append(cipherText, padText...)
	}

	plaintext = pkcs7(plaintext, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	blockMode.CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

func decryptAES256CBC(key, ciphertext, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	blockMode.CryptBlocks(plaintext, ciphertext)

	pkcs7 := func(bytes []byte) []byte {
		length := len(bytes)
		padding := int(bytes[length-1])
		return bytes[:(length - padding)]
	}
	return pkcs7(plaintext), nil
}
