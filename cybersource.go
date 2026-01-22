package cybersource

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// CaptureContext represents the decoded capture context JWT
type CaptureContext struct {
	Headers   map[string]interface{}
	Payload   CaptureContextPayload
	Signature string
	Raw       string
}

// CaptureContextPayload contains the JWT payload data
type CaptureContextPayload struct {
	Flx FlxData                  `json:"flx"`
	Ctx []map[string]interface{} `json:"ctx"`
	Iss string                   `json:"iss"`
	Exp int64                    `json:"exp"`
	Iat int64                    `json:"iat"`
	Jti string                   `json:"jti"`
}

// FlxData contains Flex-specific configuration
type FlxData struct {
	Path   string `json:"path"`
	Origin string `json:"origin"`
	JWK    JWK    `json:"jwk"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWEHeader is the header for JWE token
type JWEHeader struct {
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Enc string `json:"enc"`
}

// TokenPayload is the payload to encrypt
type TokenPayload struct {
	Data    interface{} `json:"data"`
	Context string      `json:"context"`
	Index   int         `json:"index"`
}

// CardData represents card payment data
type CardData struct {
	CARD CardDetails `json:"CARD"`
}

// CardDetails contains the actual card information
type CardDetails struct {
	Number          string `json:"number"`
	SecurityCode    string `json:"securityCode,omitempty"`
	Type            string `json:"type,omitempty"`
	ExpirationMonth string `json:"expirationMonth,omitempty"`
	ExpirationYear  string `json:"expirationYear,omitempty"`
}

// TokenResponse represents the response from CyberSource
type TokenResponse struct {
	Token string `json:"token"`
}

// FlexClient handles communication with CyberSource Flex API
type FlexClient struct {
	httpClient *http.Client
}

// NewFlexClient creates a new FlexClient
func NewFlexClient() *FlexClient {
	return &FlexClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// base64URLEncode encodes data to base64url without padding
func base64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

// base64URLDecode decodes base64url data
func base64URLDecode(s string) ([]byte, error) {
	// Add padding if needed
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// ParseCaptureContext parses a capture context JWT
func ParseCaptureContext(jwt string) (*CaptureContext, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	headerBytes, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %v", err)
	}

	payloadBytes, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %v", err)
	}

	var headers map[string]interface{}
	if err := json.Unmarshal(headerBytes, &headers); err != nil {
		return nil, fmt.Errorf("failed to parse header: %v", err)
	}

	var payload CaptureContextPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse payload: %v", err)
	}

	return &CaptureContext{
		Headers:   headers,
		Payload:   payload,
		Signature: parts[2],
		Raw:       jwt,
	}, nil
}

// IsExpired checks if the capture context has expired
func (cc *CaptureContext) IsExpired() bool {
	return time.Now().Unix() > cc.Payload.Exp
}

// GetTokenURL returns the full URL for token creation
func (cc *CaptureContext) GetTokenURL() string {
	return cc.Payload.Flx.Origin + cc.Payload.Flx.Path
}

// jwkToRSAPublicKey converts a JWK to RSA public key
func jwkToRSAPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	if jwk.Kty != "RSA" {
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}

	nBytes, err := base64URLDecode(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %v", err)
	}

	eBytes, err := base64URLDecode(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %v", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

// CreateJWE creates a JWE token for the given payload
func CreateJWE(captureContext *CaptureContext, data interface{}) (string, error) {
	// 1. Build the payload
	payload := TokenPayload{
		Data:    data,
		Context: captureContext.Raw,
		Index:   0,
	}

	plaintext, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %v", err)
	}

	// 2. Create JWE header
	header := JWEHeader{
		Kid: captureContext.Payload.Flx.JWK.Kid,
		Alg: "RSA-OAEP",
		Enc: "A256GCM",
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %v", err)
	}
	headerB64 := base64URLEncode(headerBytes)

	// 3. Generate CEK (Content Encryption Key) - 256 bits for AES-256-GCM
	cek := make([]byte, 32)
	if _, err := rand.Read(cek); err != nil {
		return "", fmt.Errorf("failed to generate CEK: %v", err)
	}

	// 4. Generate IV - 12 bytes for GCM
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("failed to generate IV: %v", err)
	}

	// 5. Encrypt CEK with RSA-OAEP (SHA-1)
	pubKey, err := jwkToRSAPublicKey(captureContext.Payload.Flx.JWK)
	if err != nil {
		return "", fmt.Errorf("failed to convert JWK: %v", err)
	}

	encryptedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pubKey, cek, nil)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt CEK: %v", err)
	}

	// 6. Encrypt plaintext with AES-256-GCM
	block, err := aes.NewCipher(cek)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	// AAD (Additional Authenticated Data) is the base64url-encoded header
	aad := []byte(headerB64)

	// Encrypt with AAD - GCM appends the auth tag to ciphertext
	ciphertextWithTag := aesGCM.Seal(nil, iv, plaintext, aad)

	// Split ciphertext and tag (tag is last 16 bytes)
	tagSize := 16
	ciphertext := ciphertextWithTag[:len(ciphertextWithTag)-tagSize]
	tag := ciphertextWithTag[len(ciphertextWithTag)-tagSize:]

	// 7. Build JWE compact serialization
	// header.encryptedKey.iv.ciphertext.tag
	jwe := fmt.Sprintf("%s.%s.%s.%s.%s",
		headerB64,
		base64URLEncode(encryptedKey),
		base64URLEncode(iv),
		base64URLEncode(ciphertext),
		base64URLEncode(tag),
	)

	return jwe, nil
}

// CreateCardJWE creates a JWE for card tokenization
func CreateCardJWE(captureContext *CaptureContext, card CardDetails) (string, error) {
	cardData := CardData{CARD: card}
	return CreateJWE(captureContext, cardData)
}

// CreateToken sends the JWE to CyberSource and returns the token
func (fc *FlexClient) CreateToken(captureContext *CaptureContext, jwe string) (string, error) {
	url := captureContext.GetTokenURL()

	req, err := http.NewRequest("POST", url, bytes.NewBufferString(jwe))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/jwt; charset=utf-8")

	resp, err := fc.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %v", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return "", fmt.Errorf("token creation failed with status %d: %s", resp.StatusCode, string(body))
	}

	return string(body), nil
}

// TokenizeCard is a convenience method that tokenizes a card in one call
func (fc *FlexClient) TokenizeCard(captureContextJWT string, card CardDetails) (string, error) {
	ctx, err := ParseCaptureContext(captureContextJWT)
	if err != nil {
		return "", fmt.Errorf("failed to parse capture context: %v", err)
	}

	if ctx.IsExpired() {
		return "", fmt.Errorf("capture context has expired")
	}

	jwe, err := CreateCardJWE(ctx, card)
	if err != nil {
		return "", fmt.Errorf("failed to create JWE: %v", err)
	}

	return fc.CreateToken(ctx, jwe)
}

// DecodeJWEHeader decodes just the header of a JWE token to extract key info
func DecodeJWEHeader(jwe string) (*JWEHeader, error) {
	parts := strings.Split(jwe, ".")
	if len(parts) != 5 {
		return nil, fmt.Errorf("invalid JWE format: expected 5 parts, got %d", len(parts))
	}

	headerBytes, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %v", err)
	}

	var header JWEHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse header: %v", err)
	}

	return &header, nil
}

// Card type constants
const (
	CardTypeVisa            = "001"
	CardTypeMastercard      = "002"
	CardTypeAmex            = "003"
	CardTypeDiscover        = "004"
	CardTypeDinersClub      = "005"
	CardTypeJCB             = "007"
	CardTypeMaestro         = "042"
	CardTypeChinaUnionPay   = "062"
	CardTypeCartesBancaires = "036"
	CardTypeElo             = "054"
	CardTypeMada            = "060"
)
