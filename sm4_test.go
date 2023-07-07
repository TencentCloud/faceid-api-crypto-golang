package faceid

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"
)

func TestEncryptSM4GCM(t *testing.T) {
	// 密钥和待加密数据
	key, _ := base64.StdEncoding.DecodeString("czdQaVpOM00zSXg3OUF4aQ==")
	plaintext := []byte("Hello, SM4-GCM!")

	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		panic(err)
	}
	fmt.Printf("iv:%s \n", base64.StdEncoding.EncodeToString(iv))
	// 加密
	ciphertext, tag, err := encryptSM4GCM(key, plaintext, iv)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("ciphertext: %s \n", base64.StdEncoding.EncodeToString(ciphertext))
	fmt.Printf("tag: %s \n", base64.StdEncoding.EncodeToString(tag))
}

func TestDecryptSM4GCM(t *testing.T) {
	// 密钥和待加密数据
	key := []byte("x9jjf8p35ywhjcmp")
	ciphertext, _ := base64.StdEncoding.DecodeString("sjIv85DmJ0YbxtI=")
	iv, _ := base64.StdEncoding.DecodeString("BEB//O5PSBh5UsAM")
	tag, _ := base64.StdEncoding.DecodeString("YnQeNEbKbPN4yiZ9gk/nlA==")
	// 解密
	plaintext, err := decryptSM4GCM(key, ciphertext, iv, tag)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("plaintext: %s\n", plaintext)
}
