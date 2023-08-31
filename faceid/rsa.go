package faceid

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
)

func loadRSAPublicKey(publicKey string) (*rsa.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	return x509.ParsePKCS1PublicKey(block.Bytes)
}

func loadRSAPrivateKey(privateKey string) (*rsa.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func encryptRSA(publicKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	keySize, srcSize := publicKey.Size(), len(plaintext)
	offSet, once := 0, keySize-11
	buffer := bytes.Buffer{}
	for offSet < srcSize {
		endIndex := offSet + once
		if endIndex > srcSize {
			endIndex = srcSize
		}
		bytesOnce, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plaintext[offSet:endIndex])
		if err != nil {
			return nil, err
		}
		buffer.Write(bytesOnce)
		offSet = endIndex
	}
	return buffer.Bytes(), nil
}

func decryptRSA(privateKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	keySize, srcSize := privateKey.Size(), len(ciphertext)
	var offSet = 0
	var buffer = bytes.Buffer{}
	for offSet < srcSize {
		endIndex := offSet + keySize
		if endIndex > srcSize {
			endIndex = srcSize
		}
		bytesOnce, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext[offSet:endIndex])
		if err != nil {
			return nil, err
		}
		buffer.Write(bytesOnce)
		offSet = endIndex
	}
	return buffer.Bytes(), nil
}
