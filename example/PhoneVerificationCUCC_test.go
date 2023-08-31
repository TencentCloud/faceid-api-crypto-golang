package example

import (
	"encoding/json"
	"github.com/tencentcloud/faceid-api-crypto-golang/faceid"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/regions"
	tencentcloudsdk "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/faceid/v20180301"
	"log"
	"testing"
)

func TestPhoneVerificationCUCC(t *testing.T) {

	var (
		Algorithm = faceid.SM4GCM // TODO 选择加密算法  Algorithm.AES256CBC、Algorithm.SM4GCM
		SecretId  = ""            // TODO 腾讯云密钥
		SecretKey = ""            // TODO 腾讯云密钥
	)

	// Step 1. 组装加密参数并对敏感数据加密
	m := make(map[string]string)
	m["Phone"] = "13800000000a"
	m["Name"] = "张三"
	m["IdCard"] = "340103202308176095"

	reqJson, err := faceid.Encrypt(Algorithm, "", m)
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("req json:%s \n", reqJson)

	// Step 2. 使用Tencent Cloud API SDK组装请求体，填充参数
	credential := common.NewCredential(SecretId, SecretKey)
	client, _ := tencentcloudsdk.NewClient(credential, regions.Guangzhou, profile.NewClientProfile())
	request := tencentcloudsdk.NewPhoneVerificationCUCCRequest()
	_ = json.Unmarshal([]byte(reqJson), request)

	// Step 3. 调用接口
	response, err := client.PhoneVerificationCUCC(request)
	if err != nil {
		if _, ok := err.(*errors.TencentCloudSDKError); ok {
			log.Printf("An API error has returned: %s", err)
			return
		}
		log.Fatalln(err)
	}
	log.Printf("%s \n", response.ToJsonString())

}
