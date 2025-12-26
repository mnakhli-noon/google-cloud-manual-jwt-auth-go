package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// #region Constants
const (
	AuthURL     = "https://oauth2.googleapis.com/token"
	Scope       = "https://www.googleapis.com/auth/SERVICE_NAME"
	GrantType   = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	KeyFile     = "service_account.json"
	TokenExpiry = 600 // 10 minutes
)

// #endregion

// #region Types
type ServiceAccount struct {
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
}

type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type JWTClaimSet struct {
	Iss   string `json:"iss"`
	Scope string `json:"scope"`
	Aud   string `json:"aud"`
	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// #endregion

func main() {
	sa, err := loadServiceAccount(KeyFile)
	if err != nil {
		log.Fatalf("Failed to load service account: %v", err)
	}

	signedJWT, err := createSignedJWT(sa)
	if err != nil {
		log.Fatalf("Failed to generate JWT: %v", err)
	}

	token, err := fetchAccessToken(signedJWT)
	if err != nil {
		log.Fatalf("Failed to fetch access token: %v", err)
	}

	fmt.Println(token)
}

// #region Helpers
func loadServiceAccount(filename string) (*ServiceAccount, error) {
	fileBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	var sa ServiceAccount
	if err := json.Unmarshal(fileBytes, &sa); err != nil {
		return nil, fmt.Errorf("parsing json: %w", err)
	}
	return &sa, nil
}

func createSignedJWT(sa *ServiceAccount) (string, error) {
	header := JWTHeader{Alg: "RS256", Typ: "JWT"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshalling header: %w", err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	now := time.Now().Unix()
	claims := JWTClaimSet{
		Iss:   sa.ClientEmail,
		Scope: Scope,
		Aud:   AuthURL,
		Iat:   now,
		Exp:   now + TokenExpiry,
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshalling claims: %w", err)
	}
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	unsignedToken := headerB64 + "." + claimsB64

	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return "", fmt.Errorf("failed to parse PEM block containing private key")
	}

	pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parsing pkcs8 key: %w", err)
	}

	rsaPrivateKey, ok := pkcs8Key.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("key is not of type *rsa.PrivateKey")
	}

	hasher := sha256.New()
	hasher.Write([]byte(unsignedToken))
	hashedDigest := hasher.Sum(nil)

	signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, crypto.SHA256, hashedDigest)
	if err != nil {
		return "", fmt.Errorf("signing token: %w", err)
	}

	signatureB64 := base64.RawURLEncoding.EncodeToString(signatureBytes)

	return unsignedToken + "." + signatureB64, nil
}

func fetchAccessToken(jwtToken string) (string, error) {
	data := url.Values{}
	data.Set("grant_type", GrantType)
	data.Set("assertion", jwtToken)

	req, err := http.NewRequest("POST", AuthURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("api returned status: %s", resp.Status)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("decoding response: %w", err)
	}

	return tokenResp.AccessToken, nil
}

// #endregion
