package faceid

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"
)

func TestAES256CBC(t *testing.T) {

	plaintext := []byte("9dfb7607-9ce5-4a60-b581-df434de04411")
	key := []byte("ibewh93B4pwqkno0VFltYhnVze80gPUr")

	iv := randomString(16)
	fmt.Printf("iv:%s \n", iv)

	// 加密
	ciphertext := encryptAES256CBC(key, plaintext, []byte(iv))

	fmt.Printf("ciphertext: %s\n", base64.StdEncoding.EncodeToString(ciphertext))
	// 解密
	decrypted := decryptAES256CBC(key, ciphertext, []byte(iv))

	fmt.Printf("plaintext: %s\n", string(decrypted))

}

func TestEncryptAES(t *testing.T) {

	plaintext := []byte("9dfb7607-9ce5-4a60-b581-df434de04411")
	key := []byte("ibewh93B4pwqkno0VFltYhnVze80gPUr")
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		panic(err)
	}
	fmt.Printf("iv:%s \n", base64.StdEncoding.EncodeToString(iv))
	// 加密
	ciphertext := encryptAES256CBC(key, plaintext, iv)
	fmt.Printf("ciphertext: %s\n", base64.StdEncoding.EncodeToString(ciphertext))
}

func TestDecryptAES(t *testing.T) {
	ciphertext, _ := base64.StdEncoding.DecodeString("1sA24aEqkayFIlnY4yX7fSMpk3s26VJ7kUewgj+lOjB3TngwciXC2You2xJYzbVf")
	key := []byte("ibewh93B4pwqkno0VFltYhnVze80gPUr")
	iv, _ := base64.StdEncoding.DecodeString("qobvAR0P5F77+Kd3lnEbWg==")
	// 解密
	decrypted := decryptAES256CBC(key, ciphertext, iv)
	fmt.Printf("plaintext: %s\n", string(decrypted))
}
