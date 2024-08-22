## API加解密DEMO

### 引入依赖

```golang
go get -u github.com/TencentCloud/faceid-api-crypto-golang/faceid@v1.0.1

```

### 接口敏感信息加解密DEMO

实名核身鉴权
[DetectAuth](example%2FDetectAuth_test.go)

获取实名核身结果信息增强版
[GetDetectInfoEnhanced](example%2FGetDetectInfoEnhanced_test.go)

获取E证通Token
[GetFaceIdToken](example%2FGetFaceIdToken_test.go)

照片人脸核身
[ImageRecognition](example%2FImageRecognition_test.go)

银行卡四要素核验
[BankCard4EVerification](example%2FBankCard4EVerification_test.go)

银行卡三要素核验
[BankCardVerification](example%2FBankCardVerification_test.go)

银行卡基础信息查询
[CheckBankCardInformation](example%2FCheckBankCardInformation_test.go)

身份信息及有效期核验
[CheckIdNameDate](example%2FCheckIdNameDate_test.go)

手机号二要素核验
[CheckPhoneAndName](example%2FCheckPhoneAndName_test.go)

身份证识别及信息核验
[IdCardOCRVerification](example%2FIdCardOCRVerification_test.go)

身份证二要素核验
[IdCardVerification](example%2FIdCardVerification_test.go)

手机号在网时长核验
[MobileNetworkTimeVerification](example%2FMobileNetworkTimeVerification_test.go)

手机号状态查询
[MobileStatus](example%2FMobileStatus_test.go)

手机号三要素核验
[PhoneVerification](example%2FPhoneVerification_test.go)

手机号三要素核验（移动）
[PhoneVerificationCMCC](example%2FPhoneVerificationCMCC_test.go)

手机号三要素核验（电信）
[PhoneVerificationCTCC](example%2FPhoneVerificationCTCC_test.go)

手机号三要素核验（联通）
[PhoneVerificationCUCC](example%2FPhoneVerificationCUCC_test.go)

身份证人像照片验真
[CheckIdCardInformation](example%2FCheckIdCardInformation_test.go)
