package faceid

import (
	"fmt"
	"log"
	"testing"
)

func TestCryptoAESEncrypt(t *testing.T) {

	tool, err := NewAPICryptoTool(`LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQU1SSm9hVWtaTjFkNU1wO
EY1VjZpdFhtU0xOTTVaNzcxYWZheW9JNDlTbmRrRnRzc3BIUzQwMloKRVVVUFFmcWJ1WmsvVnVTaDU5THRBL2ZCS3piNEJQNWJWOGFxb2dWaEc0ZS9xK0
5Ea3dsYXEwaTMxSHdMeUJsYQpFb2pFL0VFSHBYQnN1RWtWVGJLRXk1ZWxScTl0b0w3SVo4MGkrSDJtdGZVNUNQc2FyK1IzQWdNQkFBRT0KLS0tLS1FTk
QgUlNBIFBVQkxJQyBLRVktLS0tLQ==`, AES256CBC, 0)
	if err != nil {
		return
	}
	reqBody := `{
    "IdCard": "100822119610104046",
    "Name": "张三"
}`

	m := make([]string, 0)
	m = append(m, "IdCard")
	m = append(m, "Name")
	key, encryptData, err := tool.Encrypt(reqBody, m)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("key:%s \n", key)
	fmt.Printf("data:%s \n", encryptData)
}

func TestCryptoAESDecrypt(t *testing.T) {

	tool, err := NewAPICryptoTool(`LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQU1SSm9hVWtaTjFkNU1wO
EY1VjZpdFhtU0xOTTVaNzcxYWZheW9JNDlTbmRrRnRzc3BIUzQwMloKRVVVUFFmcWJ1WmsvVnVTaDU5THRBL2ZCS3piNEJQNWJWOGFxb2dWaEc0ZS9xK0
5Ea3dsYXEwaTMxSHdMeUJsYQpFb2pFL0VFSHBYQnN1RWtWVGJLRXk1ZWxScTl0b0w3SVo4MGkrSDJtdGZVNUNQc2FyK1IzQWdNQkFBRT0KLS0tLS1FTk
QgUlNBIFBVQkxJQyBLRVktLS0tLQ==`, AES256CBC, 0)
	if err != nil {
		return
	}
	rspBody := `{
  "Response": {
    "BucketName": "",
    "Encryption": {
      "Algorithm": "AES-256-CBC",
      "CiphertextBlob": "usoHovur63AGnlJhMtd+d1t5kIIbN9ManrMhVzaM2kPWy5z5PnilK5K5cBTCLbJ1aJUM1E+Bm/98SqZ8y/Woqy/pmzyyzIkwqRBk/dhHSms4EtXowAcca3mfwsYh1vKK1c0ay8A9g1Uia5wiMkHwSXAL+1Lcu5JfRpF/lxauBLU=",
      "EncryptList": [
        "Response.Text.IdCard",
        "Response.Text.Name",
        "Response.Text.OcrIdCard",
        "Response.Text.OcrName",
        "Response.Text.LivenessDetail[0].Idcard",
        "Response.Text.LivenessDetail[0].Name"
      ],
      "Iv": "ScWB6O8svtkPCJsylNOZ7g==",
      "TagList": []
    },
    "IdCardData": {
      "Avatar": null,
      "BackWarnInfos": null,
      "OcrBack": null,
      "OcrFront": null,
      "ProcessedBackImage": null,
      "ProcessedFrontImage": null,
      "WarnInfos": null
    },
    "IntentionQuestionResult": null,
    "IntentionVerifyData": null,
    "IsCustomizeStorage": false,
    "RequestId": "c95ded5f-79a2-4808-8bda-d938bcb55249",
    "Text": {
      "CompareLibType": "权威库",
      "Comparemsg": "成功",
      "Comparestatus": 0,
      "ErrCode": 0,
      "ErrMsg": "成功",
      "Extra": "",
      "IdCard": "1YpRnuliZoaL6UaCAIoCkpJCRVD7qLf4rLlSQ9NBw/o=",
      "IdInfoFrom": "手动输入",
      "LiveMsg": "成功",
      "LiveStatus": 0,
      "LivenessDetail": [
        {
          "CompareLibType": "权威库",
          "Comparemsg": "成功",
          "Comparestatus": 0,
          "Errcode": 0,
          "Errmsg": "成功",
          "Idcard": "1YpRnuliZoaL6UaCAIoCkpJCRVD7qLf4rLlSQ9NBw/o=",
          "IsNeedCharge": true,
          "Livemsg": "成功",
          "LivenessMode": 4,
          "Livestatus": 0,
          "Name": "qn8hH2biB3PGvVY2Jr+Fxw==",
          "ReqTime": "1687252487054",
          "Seq": "d07fa5b3-1a21-4080-9d86-e511ed50efe9",
          "Sim": "95.51"
        }
      ],
      "LivenessMode": 4,
      "Location": null,
      "Mobile": "",
      "NFCBillingCounts": 0,
      "NFCRequestIds": [],
      "Name": "qn8hH2biB3PGvVY2Jr+Fxw==",
      "OcrAddress": null,
      "OcrAuthority": null,
      "OcrBirth": null,
      "OcrGender": null,
      "OcrIdCard": "1YpRnuliZoaL6UaCAIoCkpJCRVD7qLf4rLlSQ9NBw/o=",
      "OcrName": "qn8hH2biB3PGvVY2Jr+Fxw==",
      "OcrNation": null,
      "OcrValidDate": null,
      "PassNo": null,
      "Sim": "95.51",
      "UseIDType": 0,
      "VisaNum": null
    },
    "VideoData": null
  }
}`
	body, err := tool.Decrypt(rspBody, "rmgk3ue5tq7ycvh6iudhc5toezj6ekcf")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("body:%s \n", body)
}

func TestCryptoSM4Encrypt(t *testing.T) {

	tool, err := NewAPICryptoTool(`LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb0VjejFVQm
dpMERRZ0FFeTJRamJLQzRMNkxKcHc1MW1qWDkwWDQxTllHYQpNcCtPR1g3ZUpCZnM4Szk4TU90S044d1BqajFpcUhVbFc2cXlQR2dnTlBJNVJHRW9BWG
Fvak9WeWNnPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t`, SM4GCM, 0)
	if err != nil {
		return
	}

	reqBody := `{
    "IdCard": "100822119610104046",
    "Name": "张三"
}`

	m := make([]string, 0)
	m = append(m, "IdCard")
	m = append(m, "Name")
	m = append(m, "Phone")
	m = append(m, "BankCard")
	key, encrypt, err := tool.Encrypt(reqBody, m)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("key:%s \n", key)
	fmt.Printf("encrypt:%s \n", encrypt)
}

func TestCryptoSM4Decrypt(t *testing.T) {

	tool, err := NewAPICryptoTool(`LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb0VjejFVQm
dpMERRZ0FFeTJRamJLQzRMNkxKcHc1MW1qWDkwWDQxTllHYQpNcCtPR1g3ZUpCZnM4Szk4TU90S044d1BqajFpcUhVbFc2cXlQR2dnTlBJNVJHRW9BW
GFvak9WeWNnPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t`, SM4GCM, 0)
	if err != nil {
		return
	}
	rspBody := `{
  "Response": {
    "BestFrame": null,
    "BucketName": "",
    "Encryption": {
      "Algorithm": "SM4-GCM",
      "CiphertextBlob": "BHzo/jDl0A2nldORvgfcH3O2rvoVk1pJQG5zKzse6sdzroE6UcigAjptMCPhltuZ01VRtqO8TB0q503SR9oI8mb5E6fUMWI/EBSKdBdVIaCUcXYvmKPPYCGZBrVJoK+IRjMd3h3rrZ5QfByFFeI6QAU=",
      "EncryptList": [
        "Response.Text.IdCard",
        "Response.Text.Name"
      ],
      "Iv": "e3wocj4HxzvPKEBz",
      "TagList": [
        "bhHcrneLtSRzj5M7cWjSYg==",
        "DHcDLyorTMZHX9UkP9QPDg=="
      ]
    },
    "IntentionQuestionResult": null,
    "IntentionVerifyData": null,
    "IsCustomizeStorage": false,
    "RequestId": "8407c504-6f10-4f5e-8ee4-9e046b55d9b3",
    "Text": {
      "CompareLibType": "",
      "Comparemsg": null,
      "Comparestatus": null,
      "ErrCode": 1003,
      "ErrMsg": "人脸识别验证未成功，请重试",
      "Extra": "",
      "IdCard": "h+4=",
      "IdInfoFrom": "手动输入",
      "LiveMsg": "人脸识别验证未成功，请重试",
      "LiveStatus": 1003,
      "LivenessMode": 4,
      "Location": null,
      "Mobile": "",
      "NFCBillingCounts": 0,
      "NFCRequestIds": [],
      "Name": "h+0=",
      "OcrAddress": null
    },
    "VideoData": null
  }
}`
	body, err := tool.Decrypt(rspBody, "r25c6t33qjbmmxgm")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("body:%s \n", body)
}
