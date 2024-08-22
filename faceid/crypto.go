package faceid

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/tjfoc/gmsm/sm2"
	"math/rand"
	"time"
)

type Algorithm string

const (
	AES256CBC Algorithm = "AES-256-CBC"
	SM4GCM    Algorithm = "SM4-GCM"
)

const (
	sm2Key = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb0VjejFVQmdpMERRZ0FFeTJRamJLQzRMNkxKcHc1MW1qWDkwWDQxTllHYQpNcCtPR1g3ZUpCZnM4Szk4TU90S044d1BqajFpcUhVbFc2cXlQR2dnTlBJNVJHRW9BWGFvak9WeWNnPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t"
	rsaKey = "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQU1SSm9hVWtaTjFkNU1wOEY1VjZpdFhtU0xOTTVaNzcxYWZheW9JNDlTbmRrRnRzc3BIUzQwMloKRVVVUFFmcWJ1WmsvVnVTaDU5THRBL2ZCS3piNEJQNWJWOGFxb2dWaEc0ZS9xK05Ea3dsYXEwaTMxSHdMeUJsYQpFb2pFL0VFSHBYQnN1RWtWVGJLRXk1ZWxScTl0b0w3SVo4MGkrSDJtdGZVNUNQc2FyK1IzQWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBLRVktLS0tLQ=="
)

func Encrypt(algorithm Algorithm, key string, args map[string]string) (string, error) {
	// 生成对称密钥
	if key == "" {
		key = GenerateKey(algorithm)
	}
	encryptList := make([]string, 0)
	tagList := make([]string, 0)
	m := make(map[string]interface{})
	// 生成随机IV
	iv := GenerateIv(algorithm)
	if len(args) != 0 {
		for k, v := range args {
			encryptList = append(encryptList, k)
			ciphertext, tag, err := EncryptData(algorithm, []byte(key), []byte(v), iv)
			if err != nil {
				return "", err
			}
			if tag != nil {
				tagList = append(tagList, base64.StdEncoding.EncodeToString(tag))
			}
			m[k] = base64.StdEncoding.EncodeToString(ciphertext)
		}
	}
	encryptKey, err := EncryptKey(algorithm, key)
	if err != nil {
		return "", err
	}
	// 组装Encryption对象
	encryption := Encryption{
		EncryptList:    encryptList,
		CiphertextBlob: encryptKey,
		Iv:             base64.StdEncoding.EncodeToString(iv),
		TagList:        tagList,
		Algorithm:      string(algorithm),
	}
	m["Encryption"] = encryption
	bytes, _ := json.Marshal(m)
	return string(bytes), nil
}

func Decrypt(algorithm Algorithm, key string, iv string, tags []string, args map[string]string) (map[string]string, error) {
	if len(args) == 0 {
		return nil, errors.New("parameter error")
	}
	if algorithm == SM4GCM {
		if len(tags) != len(args) {
			return nil, errors.New("parameter error")
		}
	}
	ivByte, err := base64.StdEncoding.DecodeString(iv)
	if err != nil {
		return nil, err
	}
	m := make(map[string]string)

	for k, v := range args {
		i := 0
		var tag []byte
		if algorithm == SM4GCM {
			tag, err = base64.StdEncoding.DecodeString(tags[i])
			if err != nil {
				return nil, err
			}
		}
		ciphertext, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, err
		}

		plaintext, err := DecryptData(algorithm, []byte(key), ciphertext, ivByte, tag)
		if err != nil {
			return nil, err
		}
		m[k] = string(plaintext)
		i++
	}
	return m, nil
}

var sm2PublicKey *sm2.PublicKey
var rsaPublicKey *rsa.PublicKey

func init() {
	sm2PublicKey, _ = loadSM2PublicKey(sm2Key)
	rsaPublicKey, _ = loadRSAPublicKey(rsaKey)
}

// EncryptKey 使用非对称算法加密对称密钥
func EncryptKey(algorithm Algorithm, key string) (string, error) {
	switch algorithm {
	case AES256CBC:
		bytes, err := encryptRSA(rsaPublicKey, []byte(key))
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(bytes), nil
	case SM4GCM:
		bytes, err := encryptSM2(sm2PublicKey, []byte(key))
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(bytes), nil
	}
	return "", errors.New("unsupported encryption algorithm")
}

// EncryptData 使用对称密钥加密明文数据
func EncryptData(algorithm Algorithm, key, plaintext, iv []byte) (ciphertext, tag []byte, err error) {
	switch algorithm {
	case AES256CBC:
		ciphertext, err = encryptAES256CBC(key, plaintext, iv)
		return
	case SM4GCM:
		ciphertext, tag, err = encryptSM4GCM(key, plaintext, iv)
		return
	}
	return
}

// DecryptData 使用对称密钥解密明文数据
func DecryptData(algorithm Algorithm, key, ciphertext, iv, tag []byte) (plaintext []byte, err error) {
	switch algorithm {
	case AES256CBC:
		return decryptAES256CBC(key, ciphertext, iv)
	case SM4GCM:
		return decryptSM4GCM(key, ciphertext, iv, tag)
	}
	return
}

// BodyEncrypt 使用对称密钥加密包体数据
func BodyEncrypt(algorithm Algorithm, key string, reqBody string) ([]byte, error) {
	// 生成对称密钥
	if key == "" {
		key = GenerateKey(algorithm)
	}
	// 生成随机IV
	iv := GenerateIv(algorithm)
	m := make(map[string]interface{})

	encryptKey, err := EncryptKey(algorithm, key)
	if err != nil {
		return nil, err
	}

	if reqBody != "" {
		tagList := make([]string, 0)
		ciphertext, tag, err := EncryptData(algorithm, []byte(key), []byte(reqBody), iv)
		if err != nil {
			return nil, err
		}
		if algorithm == SM4GCM {
			tagList = append(tagList, base64.StdEncoding.EncodeToString(tag))
		}
		encryption := &Encryption{
			Algorithm:      string(algorithm),
			EncryptList:    []string{"EncryptionBody"},
			CiphertextBlob: encryptKey,
			Iv:             base64.StdEncoding.EncodeToString(iv),
			TagList:        tagList,
		}
		m["Encryption"] = encryption
		m["EncryptedBody"] = base64.StdEncoding.EncodeToString(ciphertext)

		b, _ := json.Marshal(m)
		return b, nil
	}
	encryption := &Encryption{
		Algorithm:      string(algorithm),
		EncryptList:    []string{"EncryptionBody"},
		CiphertextBlob: encryptKey,
		Iv:             base64.StdEncoding.EncodeToString(iv),
		TagList:        nil,
	}
	m["Encryption"] = encryption
	b, _ := json.Marshal(m)
	return b, nil
}

// BodyDecrypt 使用对称密钥解密包体数据
func BodyDecrypt(algorithm Algorithm, key, iv string, tags []string, respBody string) ([]byte, error) {
	// 生成对称密钥
	if key == "" || respBody == "" {
		return nil, errors.New("parameter error")
	}
	if algorithm == SM4GCM {
		if len(tags) != 1 || tags[0] == "" {
			return nil, errors.New("parameter error")
		}
	}
	ciphertext, err := base64.StdEncoding.DecodeString(respBody)
	if err != nil {
		return nil, err
	}
	ivByte, err := base64.StdEncoding.DecodeString(iv)
	if err != nil {
		return nil, err
	}

	tag, err := base64.StdEncoding.DecodeString(tags[0])
	if err != nil {
		return nil, err
	}

	plaintext, err := DecryptData(algorithm, []byte(key), ciphertext, ivByte, tag)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func GenerateIv(algorithm Algorithm) []byte {
	switch algorithm {
	case AES256CBC:
		iv := make([]byte, 16)
		rand.Read(iv)
		return iv
	case SM4GCM:
		iv := make([]byte, 12)
		rand.Read(iv)
		return iv
	}
	return nil
}

func GenerateKey(algorithm Algorithm) string {
	switch algorithm {
	case AES256CBC:
		return randomString(32)
	case SM4GCM:
		return randomString(16)
	}
	return ""
}

// Encryption 敏感数据加密信息
type Encryption struct {
	EncryptList    []string // 加密的字段名称
	CiphertextBlob string   // 加密后的对称密钥
	Iv             string   // 初始向量
	Algorithm      string   // 加密算法
	TagList        []string // 消息摘要
}

var seed = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")

func randomString(length int) string {
	res := make([]rune, length)
	rand.Seed(time.Now().UnixNano())
	for i := range res {
		res[i] = seed[rand.Intn(len(seed))]
	}
	return string(res)
}
