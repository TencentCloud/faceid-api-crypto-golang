package faceid

import (
	"crypto/aes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/spyzhov/ajson"
	"github.com/tjfoc/gmsm/sm2"
	"math/rand"
	"time"
)

type Algorithm string

const (
	AES256CBC Algorithm = "AES-256-CBC"
	SM4GCM    Algorithm = "SM4-GCM"
)

// APICryptoTool Faceid api 加密工具
type APICryptoTool struct {
	SM2PublicKey  *sm2.PublicKey
	RSAPublicKey  *rsa.PublicKey
	keyExpireTime int64
	algorithm     Algorithm
	cache         *cache
}

// NewAPICryptoTool 初始化API加解密工具包
// publicKey 公钥信息
// algorithm 加密算法
// keyExpireTime 密钥缓存过期时间（秒）
func NewAPICryptoTool(publicKey string, algorithm Algorithm, keyExpireTime int64) (*APICryptoTool, error) {
	switch algorithm {
	case SM4GCM:
		key, err := loadSM2PublicKey(publicKey)
		if err != nil {
			return nil, err
		}
		return &APICryptoTool{
			SM2PublicKey:  key,
			keyExpireTime: keyExpireTime,
			algorithm:     algorithm,
		}, nil

	case AES256CBC:
		key, err := loadRSAPublicKey(publicKey)
		if err != nil {
			return nil, err
		}
		return &APICryptoTool{
			RSAPublicKey:  key,
			keyExpireTime: keyExpireTime,
			algorithm:     algorithm,
		}, nil
	}
	return nil, nil
}

// Encryption 敏感数据加密信息
type Encryption struct {
	EncryptList    []string // 加密的字段名称
	CiphertextBlob string   // 加密后的对称密钥
	Iv             string   // 初始向量
	Algorithm      string   // 加密算法
	TagList        []string // 消息摘要
}

// Encrypt 参数加密
func (tool *APICryptoTool) Encrypt(reqBody string, fields []string) (string, string, error) {
	switch tool.algorithm {
	case SM4GCM:
		if tool.SM2PublicKey == nil {
			return "", "", errors.New("sm2 public key not initialized")
		}
		return tool.encryptSM4(reqBody, fields)
	case AES256CBC:
		if tool.RSAPublicKey == nil {
			return "", "", errors.New("rsa public key not initialized")
		}
		return tool.encryptAES(reqBody, fields)
	}
	return "", reqBody, nil
}

// Decrypt 参数解密
func (tool *APICryptoTool) Decrypt(rspBody string, plaintextKey string) (string, error) {
	root, err := ajson.Unmarshal([]byte(rspBody))
	if err != nil {
		return "", err
	}
	key, err := root.JSONPath("$.Response.Encryption")
	if err != nil {
		return "", err
	}
	var encryption Encryption
	_ = json.Unmarshal(key[0].Source(), &encryption)

	algorithm := Algorithm(encryption.Algorithm)
	encryptList := encryption.EncryptList
	for i, field := range encryptList {
		node, err := root.JSONPath("$." + field)
		if err != nil || len(node) == 0 {
			return "", err
		}
		val, _ := node[0].GetString()
		switch algorithm {
		case SM4GCM:
			if len(encryption.EncryptList) != len(encryption.TagList) {
				return "", errors.New("encryption parameter value error")
			}
			plaintext, err := tool.decryptSM4(plaintextKey, encryption.Iv, val, encryption.TagList[i])
			if err != nil {
				return "", err
			}
			_ = node[0].Set(plaintext)
		case AES256CBC:
			plaintext, err := tool.decryptAES(plaintextKey, encryption.Iv, val)
			if err != nil {
				return "", err
			}
			_ = node[0].Set(plaintext)
		}
	}
	return root.String(), nil
}

func (tool *APICryptoTool) decryptAES(plaintextKey, ivBase64, ciphertextBase64 string) (string, error) {
	if plaintextKey == "" {
		return "", errors.New("plaintextKey cannot be empty")
	}
	iv, err := base64.StdEncoding.DecodeString(ivBase64)
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return "", err
	}
	plaintext := decryptAES256CBC([]byte(plaintextKey), ciphertext, iv)
	return string(plaintext), nil
}

func (tool *APICryptoTool) decryptSM4(plaintextKey, ivBase64, ciphertextBase64, tagBase64 string) (string, error) {
	if plaintextKey == "" {
		return "", errors.New("plaintextKey cannot be empty")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return "", err
	}
	iv, err := base64.StdEncoding.DecodeString(ivBase64)
	if err != nil {
		return "", err
	}
	tag, err := base64.StdEncoding.DecodeString(tagBase64)
	if err != nil {
		return "", err
	}
	plaintext, err := decryptSM4GCM([]byte(plaintextKey), ciphertext, iv, tag)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func (tool *APICryptoTool) encryptAES(reqBody string, fields []string) (string, string, error) {
	root, err := ajson.Unmarshal([]byte(reqBody))
	if err != nil {
		return "", "", err
	}

	params := make(map[string]string)
	for _, field := range fields {
		node, err := root.JSONPath("$." + field)
		if err != nil {
			return "", "", err
		}
		val, _ := node[0].GetString()
		params[field] = val
	}

	encryption := Encryption{
		EncryptList: make([]string, 0),
	}
	var key string
	var encryptionKey string
	if tool.keyExpireTime > 0 && tool.cache != nil {
		if time.Now().UnixNano()/1e9-tool.cache.Timestamp.UnixNano()/1e9 <= tool.keyExpireTime {
			key = tool.cache.PlaintextKey
			encryptionKey = tool.cache.CiphertextKey
		}
	}
	if key == "" || encryptionKey == "" {
		// 生成对称密钥
		key = randomString(32)
		// 加密对称密钥
		bytes, err := encryptRSA(tool.RSAPublicKey, []byte(key))
		if err != nil {
			return "", "", err
		}
		encryptionKey = base64.StdEncoding.EncodeToString(bytes)
		tool.cache = &cache{
			PlaintextKey:  key,
			CiphertextKey: encryptionKey,
			Timestamp:     time.Now(),
		}
	}
	// 生成随机iv
	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)
	// 加密数据
	for k, v := range params {
		ciphertext := encryptAES256CBC([]byte(key), []byte(v), iv)
		node, _ := root.JSONPath("$." + k)
		_ = node[0].Set(base64.StdEncoding.EncodeToString(ciphertext))
		encryption.EncryptList = append(encryption.EncryptList, k)
	}
	encryption.Iv = base64.StdEncoding.EncodeToString(iv)
	encryption.Algorithm = string(AES256CBC)
	encryption.CiphertextBlob = encryptionKey

	node := getObjectNode(encryption)
	_ = root.AppendObject("Encryption", node)
	return key, root.String(), nil
}

func (tool *APICryptoTool) encryptSM4(reqBody string, fields []string) (string, string, error) {
	root, err := ajson.Unmarshal([]byte(reqBody))
	if err != nil {
		return "", "", err
	}

	params := make(map[string]string)
	for _, field := range fields {
		node, err := root.JSONPath("$." + field)
		if err != nil {
			return "", "", err
		}
		if len(node) == 0 {
			continue
		}
		val, _ := node[0].GetString()
		params[field] = val
	}

	encryption := Encryption{
		EncryptList: make([]string, 0),
		TagList:     make([]string, 0),
	}
	// 生成对称密钥
	key := randomString(16)
	// 生成随机iv
	iv := make([]byte, 12)
	rand.Read(iv)
	// 加密对称密钥
	bytes, err := encryptSM2(tool.SM2PublicKey, []byte(key))
	if err != nil {
		return "", "", err
	}
	encryptionKey := base64.StdEncoding.EncodeToString(bytes)
	// 加密数据
	for k, v := range params {
		ciphertext, tag, err := encryptSM4GCM([]byte(key), []byte(v), iv)
		if err != nil {
			return "", "", err
		}
		node, _ := root.JSONPath("$." + k)
		_ = node[0].Set(base64.StdEncoding.EncodeToString(ciphertext))
		encryption.EncryptList = append(encryption.EncryptList, k)
		encryption.TagList = append(encryption.TagList, base64.StdEncoding.EncodeToString(tag))
	}
	encryption.Iv = base64.StdEncoding.EncodeToString(iv)
	encryption.Algorithm = string(SM4GCM)
	encryption.CiphertextBlob = encryptionKey

	node := getObjectNode(encryption)
	_ = root.AppendObject("Encryption", node)
	return key, root.String(), nil
}

var seed = []rune("abcdefghijklmnopqrstuvwxyz0123456789")

func randomString(length int) string {
	res := make([]rune, length)
	rand.Seed(time.Now().UnixNano())
	for i := range res {
		res[i] = seed[rand.Intn(len(seed))]
	}
	return string(res)
}

type cache struct {
	PlaintextKey  string
	CiphertextKey string
	Timestamp     time.Time
}

func getObjectNode(encryption Encryption) *ajson.Node {
	encryptList := make([]*ajson.Node, 0)
	for _, field := range encryption.EncryptList {
		encryptList = append(encryptList, ajson.StringNode("", field))
	}
	tagList := make([]*ajson.Node, 0)
	for _, field := range encryption.TagList {
		tagList = append(tagList, ajson.StringNode("", field))
	}
	encryptionNode := map[string]*ajson.Node{
		"Iv":             ajson.StringNode("Iv", encryption.Iv),
		"Algorithm":      ajson.StringNode("Algorithm", encryption.Algorithm),
		"CiphertextBlob": ajson.StringNode("CiphertextBlob", encryption.CiphertextBlob),
		"EncryptList":    ajson.ArrayNode("EncryptList", encryptList),
		"TagList":        ajson.ArrayNode("EncryptList", tagList),
	}
	return ajson.ObjectNode("", encryptionNode)
}
