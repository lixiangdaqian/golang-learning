package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"

	"github.com/gin-gonic/gin"
)

var privateKey *rsa.PrivateKey
var crt *x509.Certificate

type License struct {
	LicenseID          string    `json:"licenseId"`
	LicenseeName       string    `json:"licenseeName"`
	AssigneeName       string    `json:"assigneeName"`
	AssigneeEmail      string    `json:"assigneeEmail"`
	LicenseRestriction string    `json:"licenseRestriction"`
	CheckConcurrentUse bool      `json:"checkConcurrentUse"`
	Products           []Product `json:"products"`
	Metadata           string    `json:"metadata"`
	Hash               string    `json:"hash"`
	GracePeriodDays    int       `json:"gracePeriodDays"`
	AutoProlongated    bool      `json:"autoProlongated"`
	IsAutoProlongated  bool      `json:"isAutoProlongated"`
}

type Product struct {
	Code         string `json:"code"`
	FallbackDate string `json:"fallbackDate"`
	PaidUpTo     string `json:"paidUpTo"`
	Extended     bool   `json:"extended"`
}

func generateLicenseID() string {
	const allowedCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const licenseLength = 10
	b := make([]byte, licenseLength)
	for i := range b {
		index, _ := rand.Int(rand.Reader, big.NewInt(int64(len(allowedCharacters))))
		b[i] = allowedCharacters[index.Int64()]
	}
	return string(b)
}

func generateLicense(c *gin.Context) {

	var license License
	if err := c.ShouldBindJSON(&license); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	license.LicenseID = generateLicenseID()
	licenseStr, _ := json.Marshal(license)
	fmt.Printf("licenseStr:%s\n", licenseStr)
	// Sign the license using SHA1withRSA
	hashed := sha1.Sum(licenseStr)
	signature, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, hashed[:])

	licensePartBase64 := base64.StdEncoding.EncodeToString(licenseStr)
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)
	crtBase64 := base64.StdEncoding.EncodeToString(crt.Raw)

	licenseResult := fmt.Sprintf("%s-%s-%s-%s", license.LicenseID, licensePartBase64, signatureBase64, crtBase64)
	fmt.Printf("licenseResult:%s\n", licenseResult)
	c.JSON(http.StatusOK, gin.H{"license": licenseResult})
}

func index(c *gin.Context) {
	c.HTML(http.StatusOK, "/index.html", gin.H{
		"title":        "请选择",
		"licenseeName": "Evaluator",
		"assigneeName": "Evaluator",
		"expiryDate":   "2099-12-31",
	})
}

func cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method
		origin := c.Request.Header.Get("Origin")

		if origin != "" {
			c.Header("Access-Control-Allow-Origin", "*") // 可将将 * 替换为指定的域名
			c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, UPDATE")
			c.Header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization")
			c.Header("Access-Control-Expose-Headers", "Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers, Cache-Control, Content-Language, Content-Type")
			c.Header("Access-Control-Allow-Credentials", "true")
		}
		if method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
		}
		c.Next()
	}
}
func main() {
	// Load private key and certificate
	privateKeyPEM := []byte(`-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`)
	block, _ := pem.Decode(privateKeyPEM)
	privateKey, _ = x509.ParsePKCS1PrivateKey(block.Bytes)

	crtPEM := []byte(`-----BEGIN CERTIFICATE-----
MIIEtTCCAp2gAwIBAgIUDyuccmylba71lZQAQic5TJiAhwwwDQYJKoZIhvcNAQEL
BQAwGDEWMBQGA1UEAwwNSmV0UHJvZmlsZSBDQTAeFw0yMzA5MjkxNDA2MTJaFw0z
MzA5MjcxNDA2MTJaMBExDzANBgNVBAMMBk5vdmljZTCCAiIwDQYJKoZIhvcNAQEB
BQADggIPADCCAgoCggIBALenqcGP2ZxGkYqmKA9c4Hzf8+YD1smvmOxKjd+bmTLr
utM/hXv1cj1rW3/lqyDtdDk7K6W8/TDq1CRrEt+Do6l30DxhAiC34aH8DmGwgq77
xEoLimvH5LpePxflF+tbB1RZtFgFDOIYLdSQaKFH2JDgVKxhLiV3S6jniPhkCtWW
rTs+E6vq4N15Bm3NnM5AJILqjtUbOjNfaxVq6RrOoTc0R3Fqqo6yvxo/+JYa2UnH
IC+r2dbKuDLMUrtgnydEUdJNX0zH9FtcdELvr48uc9mY038TWUsZUK1pnQbxA2bP
yA4qnYJ9IvUgO6LtLXvGFm137YQMS1N41AHDBOrwoNI8UoDX+qI3rM96biFOFvn7
Edky7rByzybt3H+zxdojfjvpL1E0NO98BT9zfufHAaAxZtlmDOu5LDJe3CGurnyR
MRExbtc+Qjl1mUh6tG4lakAwdsoxry0GdG72yaYyb9it53kaFks/T/s7Z7bRJzVF
zQDV1Y4bzUtk43vKm2vztBVlQkBkZY5f2Jbe5Ig3b8swQzBnOT0mrL5SPUhwmQ6I
xkEWztj55OEujBMmRr92oESuq9ZYMaeLidKWVR3/++HA8BRZaRGEKtSHZCbFEFdi
hDxxJv9Xh6NuT/ewJ6HYp+0NQpFnUnJ72n8wV+tudpam7aKcdzVmz7cNwOhG2Ls7
AgMBAAEwDQYJKoZIhvcNAQELBQADggIBAIdeaQfKni7tXtcywC3zJvGzaaj242pS
WB1y40HW8jub0uHjTLsBPX27iA/5rb+rNXtUWX/f2K+DU4IgaIiiHhkDrMsw7piv
azqwA9h7/uA0A5nepmTYf/HY4W6P2stbeqInNsFRZXS7Jg4Q5LgEtHKo/H8USjtV
w9apmE3BCElkXRuelXMsSllpR/JEVv/8NPLmnHSY02q4KMVW2ozXtaAxSYQmZswy
P1YnBcnRukoI4igobpcKQXwGoQCIUlec8LbFXYM9V2eNCwgABqd4r67m7QJq31Y/
1TJysQdMH+hoPFy9rqNCxSq3ptpuzcYAk6qVf58PrrYH/6bHwiYPAayvvdzNPOhM
9OCwomfcazhK3y7HyS8aBLntTQYFf7vYzZxPMDybYTvJM+ClCNnVD7Q9fttIJ6eM
XFsXb8YK1uGNjQW8Y4WHk1MCHuD9ZumWu/CtAhBn6tllTQWwNMaPOQvKf1kr1Kt5
etrONY+B6O+Oi75SZbDuGz7PIF9nMPy4WB/8XgKdVFtKJ7/zLIPHgY8IKgbx/VTz
6uBhYo8wOf3xzzweMnn06UcfV3JGNvtMuV4vlkZNNxXeifsgzHugCvJX0nybhfBh
fIqVyfK6t0eKJqrvp54XFEtJGR+lf3pBfTdcOI6QFEPKGZKoQz8Ck+BC/WBDtbjc
/uYKczZ8DKZu
-----END CERTIFICATE-----`)
	block, _ = pem.Decode(crtPEM)
	crt, _ = x509.ParseCertificate(block.Bytes)
	//初始化路由
	r := gin.Default()
	r.Use(cors())
	r.Static("static", "static")
	//加载模板
	r.LoadHTMLGlob("templates/*")
	r.GET("/", index)
	r.POST("/generateLicense", generateLicense)
	r.Run("0.0.0.0:8080")
}
