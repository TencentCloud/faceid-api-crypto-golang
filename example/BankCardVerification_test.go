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

func TestBankCardVerification(t *testing.T) {

	var (
		Algorithm = faceid.SM4GCM // TODO 选择加密算法  Algorithm.AES256CBC、Algorithm.SM4GCM
		SecretId  = ""            // TODO 腾讯云密钥
		SecretKey = ""            // TODO 腾讯云密钥
	)

	// Step 1. 组装加密参数并对敏感数据加密
	m := make(map[string]string)
	m["BankCard"] = "9802897613438987"
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
	request := tencentcloudsdk.NewBankCardVerificationRequest()
	_ = json.Unmarshal([]byte(reqJson), request)

	// Step 3. TODO 根据您的业务需要，设置其他参数，详情参考api文档：https://cloud.tencent.com/document/product/1007/33848

	// Step 4. 调用接口
	response, err := client.BankCardVerification(request)
	if err != nil {
		if _, ok := err.(*errors.TencentCloudSDKError); ok {
			log.Printf("An API error has returned: %s", err)
			return
		}
		log.Fatalln(err)
	}
	log.Printf("%s \n", response.ToJsonString())

}
