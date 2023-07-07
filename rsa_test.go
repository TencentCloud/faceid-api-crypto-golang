package faceid

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"testing"
)

func TestGenRsaKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	bytes := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: bytes,
	}
	fmt.Println(string(pem.EncodeToMemory(block)))

	publicKey := &privateKey.PublicKey
	derPkix := x509.MarshalPKCS1PublicKey(publicKey)
	if err != nil {
		panic(err)
	}
	block = &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: derPkix,
	}
	fmt.Println(string(pem.EncodeToMemory(block)))
}

func TestLoadRSAPublicKey(t *testing.T) {
	key := `LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQU1SSm9hVWtaTjFkNU1wOEY1VjZpdFhtU0xOTTVaNzcxYWZheW9JN
DlTbmRrRnRzc3BIUzQwMloKRVVVUFFmcWJ1WmsvVnVTaDU5THRBL2ZCS3piNEJQNWJWOGFxb2dWaEc0ZS9xK05Ea3dsYXEwaTMxSHdMeUJsYQpFb2pFL0
VFSHBYQnN1RWtWVGJLRXk1ZWxScTl0b0w3SVo4MGkrSDJtdGZVNUNQc2FyK1IzQWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBLRVktLS0tLQ==`

	publicKey, err := loadRSAPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(publicKey.Size())
}

func TestLoadRSAPrivateKey(t *testing.T) {
	key := ``

	privateKey, err := loadRSAPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(privateKey.Size())
}

func TestRsaEncrypt(t *testing.T) {
	data := []byte("haha")

	key := `LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQU1SSm9hVWtaTjFkNU1wOEY1VjZpdFhtU0xOTTVaNzcxYWZheW9JN
DlTbmRrRnRzc3BIUzQwMloKRVVVUFFmcWJ1WmsvVnVTaDU5THRBL2ZCS3piNEJQNWJWOGFxb2dWaEc0ZS9xK05Ea3dsYXEwaTMxSHdMeUJsYQpFb2pFL0
VFSHBYQnN1RWtWVGJLRXk1ZWxScTl0b0w3SVo4MGkrSDJtdGZVNUNQc2FyK1IzQWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBLRVktLS0tLQ==`

	publicKey, err := loadRSAPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := encryptRSA(publicKey, data)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(ciphertext))
}

func TestRsaDecrypt(t *testing.T) {
	ciphertext := `KO9G3MRAs9z8cOz5g1u0C5Et9QHSRsk9W4frgKMUJJFsTqqBCqChPHC76r2YFAPCNQusQjz1kvv1CtD4xI6o5WfPnZZK58xQM5Xbt9q/q9ev3DIkkvGHw2gEYe+E1pbx8LFoPN6E8Lt339zpjR1WhTRGgM/rHCcGINbOlXATei4=`
	b, _ := base64.StdEncoding.DecodeString(ciphertext)

	key := ``

	privateKey, err := loadRSAPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := decryptRSA(privateKey, b)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(plaintext))
}
