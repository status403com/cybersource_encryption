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
	mRand "math/rand/v2"
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

// CheckData represents ACH/eCheck payment data
type CheckData struct {
	CHECK CheckDetails `json:"CHECK"`
}

// CheckDetails contains the actual check/ACH information
type CheckDetails struct {
	Account       AccountDetails `json:"account"`
	RoutingNumber string         `json:"routingNumber"`
}

// AccountDetails contains bank account information
type AccountDetails struct {
	Number        string `json:"number"`
	NumberConfirm string `json:"numberConfirm,omitempty"`
	Type          string `json:"type"` // C=Checking, S=Savings, X=Corporate
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

// CreateCheckJWE creates a JWE for ACH/eCheck tokenization
func CreateCheckJWE(captureContext *CaptureContext, check CheckDetails) (string, error) {
	checkData := CheckData{CHECK: check}
	return CreateJWE(captureContext, checkData)
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

// TokenizeCheck is a convenience method that tokenizes a check/ACH in one call
func (fc *FlexClient) TokenizeCheck(captureContextJWT string, check CheckDetails) (string, error) {
	ctx, err := ParseCaptureContext(captureContextJWT)
	if err != nil {
		return "", fmt.Errorf("failed to parse capture context: %v", err)
	}

	if ctx.IsExpired() {
		return "", fmt.Errorf("capture context has expired")
	}

	jwe, err := CreateCheckJWE(ctx, check)
	if err != nil {
		return "", fmt.Errorf("failed to create JWE: %v", err)
	}

	return fc.CreateToken(ctx, jwe)
}

// EncodeCard is a convenience method that encodes a card using JWE in one call
func (fc *FlexClient) EncodeCard(captureContextJWT string, card CardDetails) (string, error) {
	ctx, err := ParseCaptureContext(captureContextJWT)
	if err != nil {
		return "", fmt.Errorf("failed to parse capture context: %v", err)
	}

	if ctx.IsExpired() {
		return "", fmt.Errorf("capture context has expired")
	}

	return CreateCardJWE(ctx, card)
}

// EncodeCheck is a convenience method that encodes a check/ACH using JWE in one call
func (fc *FlexClient) EncodeCheck(captureContextJWT string, check CheckDetails) (string, error) {
	ctx, err := ParseCaptureContext(captureContextJWT)
	if err != nil {
		return "", fmt.Errorf("failed to parse capture context: %v", err)
	}

	if ctx.IsExpired() {
		return "", fmt.Errorf("capture context has expired")
	}

	return CreateCheckJWE(ctx, check)
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

// ParseIframeURL extracts the capture context from a full Flex Microform iframe URL
// Example URL: https://flex.cybersource.com/.../iframe.html?keyId=xxx#%7B%22jwt%22%3A%22eyJ...
func ParseIframeURL(iframeURL string) (*CaptureContext, error) {
	// Find the hash fragment
	hashIndex := strings.Index(iframeURL, "#")
	if hashIndex < 0 {
		return nil, fmt.Errorf("no hash fragment found in URL")
	}

	hash := iframeURL[hashIndex:]
	return ParseIframeHash(hash)
}

// ParseIframeHash parses the hash fragment from a Flex Microform iframe URL
// The hash contains URL-encoded JSON with the capture context
func ParseIframeHash(hash string) (*CaptureContext, error) {
	// Remove leading # if present
	hash = strings.TrimPrefix(hash, "#")

	// URL decode
	decoded, err := decodeURIComponent(hash)
	if err != nil {
		return nil, fmt.Errorf("failed to URL decode hash: %v", err)
	}

	// Parse JSON
	var params struct {
		JWT             string                 `json:"jwt"`
		MicroformID     string                 `json:"microformId"`
		MicroformType   string                 `json:"microformType"`
		FieldID         string                 `json:"fieldId"`
		FieldType       string                 `json:"fieldType"`
		Config          map[string]interface{} `json:"config"`
		MicroformConfig map[string]interface{} `json:"microformConfig"`
	}

	if err := json.Unmarshal([]byte(decoded), &params); err != nil {
		return nil, fmt.Errorf("failed to parse hash JSON: %v", err)
	}

	if params.JWT == "" {
		return nil, fmt.Errorf("no JWT found in hash")
	}

	return ParseCaptureContext(params.JWT)
}

// decodeURIComponent mimics JavaScript's decodeURIComponent
func decodeURIComponent(s string) (string, error) {
	// Replace + with space, then unescape
	s = strings.ReplaceAll(s, "+", " ")

	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if h, err := hexDecode(s[i+1 : i+3]); err == nil {
				result = append(result, h)
				i += 2
				continue
			}
		}
		result = append(result, s[i])
	}
	return string(result), nil
}

func hexDecode(s string) (byte, error) {
	if len(s) != 2 {
		return 0, fmt.Errorf("invalid hex")
	}
	var b byte
	for i := 0; i < 2; i++ {
		b <<= 4
		c := s[i]
		switch {
		case '0' <= c && c <= '9':
			b |= c - '0'
		case 'a' <= c && c <= 'f':
			b |= c - 'a' + 10
		case 'A' <= c && c <= 'F':
			b |= c - 'A' + 10
		default:
			return 0, fmt.Errorf("invalid hex char")
		}
	}
	return b, nil
}

func GenerateBrParamValue() string {
	return fmt.Sprintf("%d", int(900000*mRand.Float64())+100000)
}
func GenerateBrParamValueWithCustomRand(source *mRand.Rand) string {
	return fmt.Sprintf("%d", int(900000*source.Float64())+100000)
}

// Card type constants
type CardType string

const (
	CardTypeVisa            CardType = "001"
	CardTypeMastercard      CardType = "002"
	CardTypeAmex            CardType = "003"
	CardTypeDiscover        CardType = "004"
	CardTypeDinersClub      CardType = "005"
	CardTypeJCB             CardType = "007"
	CardTypeCartesBancaires CardType = "036"
	CardTypeUATP            CardType = "040"
	CardTypeMaestro         CardType = "042"
	CardTypeJCrew           CardType = "046"
	CardTypeElo             CardType = "054"
	CardTypeCarnet          CardType = "058"
	CardTypeMada            CardType = "060"
	CardTypeChinaUnionPay   CardType = "062"
	CardTypeKCP             CardType = "065"
	CardTypeMeeza           CardType = "067"
	CardTypePayPak          CardType = "068"
	CardTypeEftpos          CardType = "070"
	CardTypeJaywan          CardType = "081"
)

// Account type constants
const (
	AccountTypeChecking  = "C"
	AccountTypeSavings   = "S"
	AccountTypeCorporate = "X"
)

var CardTypeBrandedNames = map[CardType]string{
	CardTypeVisa:            "Visa",
	CardTypeMastercard:      "Mastercard",
	CardTypeAmex:            "American Express",
	CardTypeDiscover:        "Discover",
	CardTypeDinersClub:      "Diners Club",
	CardTypeUATP:            "UATP",
	CardTypeJCB:             "JCB",
	CardTypeCartesBancaires: "Cartes Bancaires",
	CardTypeMaestro:         "Maestro",
	CardTypeJCrew:           "J.Crew",
	CardTypeElo:             "Elo",
	CardTypeCarnet:          "Carnet",
	CardTypeMada:            "Mada",
	CardTypeChinaUnionPay:   "China UnionPay",
	CardTypeKCP:             "Korea Cyber Payment",
	CardTypeMeeza:           "Meeza",
	CardTypePayPak:          "PayPak",
	CardTypeEftpos:          "eftpos",
	CardTypeJaywan:          "Jaywan",
}
