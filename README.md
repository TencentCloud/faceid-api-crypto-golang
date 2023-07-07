API加解密SDK说明

```bash
$ go get -u github.com/TencentCloud/faceid-api-crypto-golang
```

### 1. SDK初始化

```
// publicKey：登陆人脸核身控制台获取公钥，如果使用AES-256-CBC算法，公钥选择RSA公钥；如果使用SM4-GCM算法，公钥选择SM2公钥
// algorithm：指定加密算法（AES-256-CBC或SM4GCM）
// keyExpireTime：对称密钥过期时间，在过期时间内生成的对称密钥可复用。0表示不复用密钥
instance, err := faceid.NewAPICryptoTool(publicKey, algorithm, keyExpireTime)
```

### 2. 入参加密

```
// reqBody：明文请求参数
// fields：要加密的字段列表
// plaintextKey：生成的对称密钥明文
// req：加密的请求参数
plaintextKey, req, err := instance.Encrypt(reqBody, fields)

example:
输入：
reqBody := `{
    "Action": "BankCardVerification",
    "Version": "2018-03-01",
    "IdCard": "621103145623471011",
    "Name": "张三",
    "BankCard": "6214865712375011",
    "CertType": 0
}`
fields:= []string{"IdCard","Name"}

plaintextKey, req, err := instance.Encrypt(reqBody, fields)
fmt.Print(plaintextKey)
fmt.Print(req)
```

### 3. 出参加密

```
// reqBody：明文请求参数
// plaintextKey：对称密钥明文
// req：加密的请求参数
plaintextKey, req, err := instance.Encrypt(reqBody, nil)

// rspBody：接口响应
// plaintextKey：对称密钥明文
// rsp：解密后的明文响应
rsp, err := instance.Decrypt(rspBody, plaintextKey)

example：
{
  "Action": "GetDetectInfoEnhanced",
  "RuleId": '2',
  "BizToken": '37C8960C-4673-4152-8122-1433C305C144'
}
plaintextKey, req, err := instance.Encrypt(reqBody, nil)
fmt.Print(plaintextKey)
fmt.Print(req)
// 发送请求获得回包rsp
// 此处mock一个，rsp一定带有Encryption字段
rsp = {
  Response: {
    "Encryption": {
      "Algorithm": "AES-256-CBC",
      "CiphertextBlob": "DCaa541gYPA8ybDaAasY4C17K5CHo3s8/ZDNsaS8hH8Gr+qnA9RY53QswVOY4smcJsv5ToXPN6qOqruT9QVw5VPVglQ5YO60RjWabZKA+sF3BxDRMmrnuTKMNPwswen1mG4SfotyJ4IVv4PHomPZwzlZtGjm0CkXvgmnaHLxkck=",
      "EncryptList": [
        "Response.Text.IdCard",
        "Response.Text.Name",
      ],
      "Iv": "vTjCqg1Xz6Lh0pJZCNjAAQ==",
      "TagList": [],
    },
    "RequestId": "d55782f3-dc0f-4484-a067-ff2046fe659e",
    "Text": {
      "IdCard": "8TEJyC4YWALmK5U9cw+R+1Rvs4LuNRAAm8LQkwrJEa4=",
      "Name": "QR3meQHDzArXCIuJIyETLzRtOjg0vjRxcYdKQTOE7vw=",
    },
  }
}

rsp, err := instance.Decrypt(rsp, plaintextKey)
fmt.Print(rsp)

```

### 4. 出入参都加密

```
// reqBody：明文请求参数
// plaintextKey：对称密钥明文
// req：加密的请求参数
plaintextKey, req, err := instance.Encrypt(reqBody, fields)

// rspBody：接口响应
// plaintextKey：对称密钥明文
// rsp：解密后的明文响应
rsp, err := instance.Decrypt(rspBody, plaintextKey)


example:
req :={
  "IdCard": "440111111111111111",
  "Name": "爱新觉罗永琪",
  "RuleId": "2",
  "BizToken": "37C8960C-4673-4152-8122-1433C305C144"
}
fields:= []string{"IdCard","Name"}

plaintextKey, req, err := instance.Encrypt(reqBody, fields)
fmt.Print(plaintextKey)
fmt.Print(req)

// 发送请求获得回包
// 此处mock一个，rsp一定带有Encryption字段。
rsp = {
  "Response: {
    "Encryption: {
      "Algorithm: 'SM4-GCM',
      "CiphertextBlob: 'BC3JNqinBaASuOhjP/WCkrCgtLm03d/stJMh1QgPKfdFoVdpySbZNah6iUIhoSI+EPML8dDgXJE2wkSZv8x029v+t2VoC6Lc6RW1gowi2tqwz2SNmb4qN/VrqMi1a3m/T3gXY42AbvORP90Jxqgr3hE=',
      "EncryptList: [
        "Response.Text.IdCard",
        "Response.Text.Name",
      ],
      "Iv": "cHNm8k09p2d80owr",
      "TagList": [
        "meBiloynTRhQtOtLR2xccQ==",
        "Anrq6V9s4jwBg+/mxW9Zeg==",
      ],
    },
    "Text: {
      "IdCard": "oUfaRWLLjR9MclkyFF68M7Ot",
      "Name": "cvtbksVKVIn0pNWUw9815RI2",
    }
  }
};

rsp, err := instance.Decrypt(rsp, plaintextKey)
fmt.Print(rsp)

```



