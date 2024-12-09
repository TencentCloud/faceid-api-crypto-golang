package example

import (
	"encoding/json"
	"github.com/TencentCloud/faceid-api-crypto-golang/faceid"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/regions"
	tencentcloudsdk "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/faceid/v20180301"
	"log"
	"testing"
)

func TestCheckIdCardInformation(t *testing.T) {
	var (
		Algorithm = faceid.SM4GCM // TODO 选择加密算法  Algorithm.AES256CBC、Algorithm.SM4GCM
		SecretId  = ""            // TODO 腾讯云密钥
		SecretKey = ""            // TODO 腾讯云密钥
	)
	// Step 1. 生成对称密钥，用于加解密敏感信息
	key := faceid.GenerateKey(Algorithm)

	// Step 2. 生成加密参数
	reqJson, err := faceid.BodyEncrypt(Algorithm, key, "")
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("ciphertext desc:%s", reqJson)

	// Step 3. 使用Tencent Cloud API SDK组装请求体，填充参数
	credential := common.NewCredential(SecretId, SecretKey)
	client, _ := tencentcloudsdk.NewClient(credential, regions.Guangzhou, profile.NewClientProfile())
	request := tencentcloudsdk.NewCheckIdCardInformationRequest()
	err = json.Unmarshal(reqJson, request)
	if err != nil {
		log.Fatalln(err)
	}

	// Step 4. TODO 根据您的业务需要，设置其他参数，详情参考api文档：https://cloud.tencent.com/document/product/1007/47276
	request.ImageBase64 = common.StringPtr("")
	request.IsEncryptResponse = common.BoolPtr(true)

	// Step 5. 调用接口
	response, err := client.CheckIdCardInformation(request)
	if err != nil {
		if _, ok := err.(*errors.TencentCloudSDKError); ok {
			log.Printf("An API error has returned: %s", err)
			return
		}
		log.Fatalln(err)
	}
	log.Printf("ciphertext response: %s", response.ToJsonString())

	// Step 6. 解密接敏感信息
	var tagList []*string
	if Algorithm == faceid.SM4GCM {
		tagList = response.Response.Encryption.TagList
	}
	plaintext, err := faceid.BodyDecrypt(Algorithm, key, *response.Response.Encryption.Iv, tagList, *response.Response.EncryptedBody)
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("plaintext response: %s", string(plaintext))
}
