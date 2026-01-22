package cybersource

import (
	"fmt"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestDecodeJWE(t *testing.T) {
	// This is a JWE token (5 parts) - the ENCRYPTED payload sent TO CyberSource
	// NOT the capture context (which is a JWT with 3 parts)
	jweToken := "JWE_TOKEN_HERE"

	// Decode the JWE header to see the key ID used
	header, err := DecodeJWEHeader(jweToken)
	if err != nil {
		t.Fatalf("Failed to decode JWE header: %v", err)
	}

	fmt.Printf("JWE Header:\n")
	fmt.Printf("  Key ID (kid): %s\n", header.Kid)
	fmt.Printf("  Algorithm: %s\n", header.Alg)
	fmt.Printf("  Encryption: %s\n", header.Enc)
}

func TestParseCaptureContext(t *testing.T) {
	// A proper capture context JWT has 3 parts (header.payload.signature)

	// Example token:
	captureContextJWT := `JWT_TOKEN_HERE`

	ctx, err := ParseCaptureContext(captureContextJWT)
	if err != nil {
		t.Logf("Parse error: %v", err)
		return
	}

	fmt.Printf("Parsed Capture Context:\n")
	fmt.Printf("  Origin: %s\n", ctx.Payload.Flx.Origin)
	fmt.Printf("  Path: %s\n", ctx.Payload.Flx.Path)
	fmt.Printf("  Key ID: %s\n", ctx.Payload.Flx.JWK.Kid)
	fmt.Printf("  Expired: %v\n", ctx.IsExpired())
	fmt.Printf("  Token URL: %s\n", ctx.GetTokenURL())
}

func TestTokenizeCard(t *testing.T) {
	client := NewFlexClient()

	// You need a valid capture context from CyberSource
	captureContextJWT := "JWT_TOKEN_HERE"

	card := CardDetails{
		Number:          "4111111111111111",
		SecurityCode:    "123",
		Type:            CardTypeVisa,
		ExpirationMonth: "12",
		ExpirationYear:  "2026",
	}

	token, err := client.TokenizeCard(captureContextJWT, card)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Token: %s\n", token)
}

func parsePaymentToken(encoded string) (string, error) {
	token, _, err := jwt.NewParser().ParseUnverified(encoded, jwt.MapClaims{})
	if err != nil {
		return "", err
	}

	claims := token.Claims.(jwt.MapClaims)
	jti, ok := claims["jti"]
	if !ok {
		return "", fmt.Errorf("token not found")
	}

	parsed, ok := jti.(string)
	if !ok {
		return "", fmt.Errorf("failed to parse token")
	}

	return parsed, nil
}
