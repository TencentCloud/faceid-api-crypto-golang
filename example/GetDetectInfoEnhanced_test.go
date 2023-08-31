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

func TestGetDetectInfoEnhanced(t *testing.T) {

	var (
		Algorithm = faceid.SM4GCM // TODO 选择加密算法  Algorithm.AES256CBC、Algorithm.SM4GCM
		SecretId  = ""            // TODO 腾讯云密钥
		SecretKey = ""            // TODO 腾讯云密钥
	)

	// Step 1. 生成对称密钥，用于加解密敏感信息
	key := faceid.GenerateKey(Algorithm)

	// Step 2. 组装加密参数并对敏感数据加密
	reqJson, err := faceid.Encrypt(Algorithm, key, nil)
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("req json:%s \n", reqJson)

	// Step 2. 使用Tencent Cloud API SDK组装请求体，填充参数
	credential := common.NewCredential(SecretId, SecretKey)
	client, _ := tencentcloudsdk.NewClient(credential, regions.Guangzhou, profile.NewClientProfile())
	request := tencentcloudsdk.NewGetDetectInfoEnhancedRequest()
	_ = json.Unmarshal([]byte(reqJson), request)

	// Step 4. TODO 根据您的业务需要，设置其他参数，详情参考api文档：https://cloud.tencent.com/document/product/1007/41957
	request.RuleId = common.StringPtr("")
	request.InfoType = common.StringPtr("")
	request.BizToken = common.StringPtr("")

	// Step 5. 调用接口
	response, err := client.GetDetectInfoEnhanced(request)
	if err != nil {
		if _, ok := err.(*errors.TencentCloudSDKError); ok {
			log.Printf("An API error has returned: %s", err)
			return
		}
		log.Fatalln(err)
	}
	log.Printf("%s \n", response.ToJsonString())

	// Step 6. 组装需要解密的参数
	m := make(map[string]string)
	m["Response.Text.IdCard"] = *response.Response.Text.IdCard
	m["Response.Text.Name"] = *response.Response.Text.Name
	m["Response.Text.OcrIdCard"] = *response.Response.Text.OcrIdCard
	m["Response.Text.OcrName"] = *response.Response.Text.OcrName
	m["Response.Text.LivenessDetail[0].Idcard"] = *response.Response.Text.LivenessDetail[0].Idcard
	m["Response.Text.LivenessDetail[0].Name"] = *response.Response.Text.LivenessDetail[0].Name
	tagList := common.StringValues(response.Response.Encryption.TagList)
	iv := *response.Response.Encryption.Iv

	// Step 7. 解密接敏感信息
	resultMap, err := faceid.Decrypt(Algorithm, key, iv, tagList, m)
	if err != nil {
		log.Fatalln(err)
	}
	for k, v := range resultMap {
		log.Printf("key:%s value:%s \n", k, v)
	}

}

// Response 示例
// {
//    "Response": {
//        "Text": {
//            "ErrCode": 2006,
//            "ErrMsg": "姓名和身份证号不匹配，请核实身份后重试",
//            "IdCard": "wueSQRrp69xBMjJxXX5eCfcP",
//            "UseIDType": 0,
//            "Name": "EWkAlJJR",
//            "OcrNation": null,
//            "OcrAddress": null,
//            "OcrBirth": null,
//            "OcrAuthority": null,
//            "OcrValidDate": null,
//            "OcrName": "EWkAlJJR",
//            "OcrIdCard": "wueSQRrp69xBMjJxXX5eCfcP",
//            "OcrGender": null,
//            "IdInfoFrom": "手动输入",
//            "LiveStatus": 0,
//            "LiveMsg": "成功",
//            "Comparestatus": 2006,
//            "Comparemsg": "姓名和身份证号不匹配，请核实身份后重试",
//            "CompareLibType": "权威库",
//            "LivenessMode": 3,
//            "Sim": "0.00",
//            "Location": null,
//            "Mobile": "",
//            "NFCRequestIds": [],
//            "NFCBillingCounts": 0,
//            "Extra": "",
//            "LivenessDetail": [
//                {
//                    "ReqTime": "1692272463607",
//                    "Seq": "6a45d7d6-2c3a-4ebb-8977-f17571f5844c",
//                    "Idcard": "wueSQRrp69xBMjJxXX5eCfcP",
//                    "Name": "EWkAlJJR",
//                    "Sim": "0.00",
//                    "IsNeedCharge": true,
//                    "Errcode": 2006,
//                    "Errmsg": "姓名和身份证号不匹配，请核实身份后重试",
//                    "Livestatus": 0,
//                    "Livemsg": "成功",
//                    "Comparestatus": 2006,
//                    "Comparemsg": "姓名和身份证号不匹配，请核实身份后重试",
//                    "CompareLibType": "权威库",
//                    "LivenessMode": 3
//                }
//            ],
//            "PassNo": null,
//            "VisaNum": null
//        },
//        "IdCardData": null,
//        "BestFrame": null,
//        "VideoData": null,
//        "IsCustomizeStorage": false,
//        "BucketName": "",
//        "IntentionVerifyData": null,
//        "IntentionQuestionResult": null,
//        "IntentionActionResult": null,
//        "RequestId": "e907d58c-2069-48a4-beb6-691fb3eafcfd",
//        "Encryption": {
//            "Algorithm": "SM4-GCM",
//            "CiphertextBlob": "BJr625A7qLxvp784g2A+rXN5OTcp9uoL0LLShyfQi6TtwDUkfqJEw6+cwepexe0IjwsQYSlXYeY221Ao0OaSU16DjQ/xj8PcL08XcSFVUk2w4rb4jpEedQ7JVoxP98AwExFA2PqzU/lG9M6nkSiz1d0=",
//            "EncryptList": [
//                "Response.Text.IdCard",
//                "Response.Text.Name",
//                "Response.Text.OcrIdCard",
//                "Response.Text.OcrName",
//                "Response.Text.LivenessDetail[0].Idcard",
//                "Response.Text.LivenessDetail[0].Name"
//            ],
//            "TagList": [
//                "rIZ3ATfhaKWgo5Yxiuz0xw==",
//                "ODTnlmCGm1253czvBm+lYQ==",
//                "rIZ3ATfhaKWgo5Yxiuz0xw==",
//                "ODTnlmCGm1253czvBm+lYQ==",
//                "rIZ3ATfhaKWgo5Yxiuz0xw==",
//                "ODTnlmCGm1253czvBm+lYQ=="
//            ],
//            "Iv": "vP5I2L8GVqav5Da8"
//        }
//    }
//}
