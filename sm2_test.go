package faceid

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
	"testing"
)

func TestGenerateSM2Key(t *testing.T) {
	privateKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyBytes, err := x509.MarshalSm2PrivateKey(privateKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	block := &pem.Block{
		Type:  "SM2 PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	fmt.Println(string(pem.EncodeToMemory(block)))
	fmt.Println(x509.WritePrivateKeyToHex(privateKey))

	publicKey := &privateKey.PublicKey
	publicKeyBytes, err := x509.MarshalSm2PublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	fmt.Println(string(pem.EncodeToMemory(block)))
	fmt.Println(x509.WritePublicKeyToHex(publicKey))

}

func TestEncryptSM2(t *testing.T) {
	key := `LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb0VjejFVQmdpMERRZ0FFeTJRamJLQzRMNkxKcHc1MW
1qWDkwWDQxTllHYQpNcCtPR1g3ZUpCZnM4Szk4TU90S044d1BqajFpcUhVbFc2cXlQR2dnTlBJNVJHRW9BWGFvak9WeWNnPT0KLS0tLS1FTkQgUFVCTE
lDIEtFWS0tLS0t`

	publicKey, err := loadSM2PublicKey(key)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(x509.WritePublicKeyToHex(publicKey))
	ciphertext, err := encryptSM2(publicKey, []byte("hello sm2 hello sm2"))
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("%s \n", base64.StdEncoding.EncodeToString(ciphertext))

}

func TestDecryptSM2(t *testing.T) {

	key := ``

	privateKey, err := loadSM2PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, _ := base64.StdEncoding.DecodeString("BHzo/jDl0A2nldORvgfcH3O2rvoVk1pJQG5zKzse6sdzroE6UcigAjptMCPhltuZ01VRtqO8TB0q503SR9oI8mb5E6fUMWI/EBSKdBdVIaCUcXYvmKPPYCGZBrVJoK+IRjMd3h3rrZ5QfByFFeI6QAU=")
	if err != nil {
		t.Fatal(err)
	}
	plainText, err := decryptSM2(privateKey, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(string(plainText))

}
