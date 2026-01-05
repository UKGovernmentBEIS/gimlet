package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Generate test keypair
func generateTestKeyPair(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	return privateKey, &privateKey.PublicKey
}

func TestValidateAgentJWT_Valid(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)
	validator := NewJWTValidator([]*rsa.PublicKey{publicKey}, "gimlet-test")

	// Create valid agent token
	claims := AgentClaims{
		Service: "test-service",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "agent-1",
			Issuer:    "gimlet-test",
			Audience:  jwt.ClaimStrings{"gimlet-agent"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	agentID, service, expiresAt, err := validator.ValidateAgentJWT(tokenString)
	if err != nil {
		t.Fatalf("Expected valid token, got error: %v", err)
	}

	if agentID != "agent-1" {
		t.Errorf("Expected agentID 'agent-1', got '%s'", agentID)
	}
	if service != "test-service" {
		t.Errorf("Expected service 'test-service', got '%s'", service)
	}
	if expiresAt.IsZero() {
		t.Error("Expected non-zero expiry time")
	}
}

func TestValidateAgentJWT_WrongAudience(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)
	validator := NewJWTValidator([]*rsa.PublicKey{publicKey}, "gimlet-test")

	claims := AgentClaims{
		Service: "test-service",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "agent-1",
			Issuer:    "gimlet-test",
			Audience:  jwt.ClaimStrings{"gimlet-client"}, // Wrong!
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, _ := token.SignedString(privateKey)

	_, _, _, err := validator.ValidateAgentJWT(tokenString)
	if err == nil {
		t.Error("Expected error for wrong audience, got nil")
	}
}

func TestValidateAgentJWT_WrongIssuer(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)
	validator := NewJWTValidator([]*rsa.PublicKey{publicKey}, "gimlet-test")

	claims := AgentClaims{
		Service: "test-service",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "agent-1",
			Issuer:    "evil-issuer", // Wrong!
			Audience:  jwt.ClaimStrings{"gimlet-agent"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, _ := token.SignedString(privateKey)

	_, _, _, err := validator.ValidateAgentJWT(tokenString)
	if err == nil {
		t.Error("Expected error for wrong issuer, got nil")
	}
}

func TestValidateAgentJWT_Expired(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)
	validator := NewJWTValidator([]*rsa.PublicKey{publicKey}, "gimlet-test")

	claims := AgentClaims{
		Service: "test-service",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "agent-1",
			Issuer:    "gimlet-test",
			Audience:  jwt.ClaimStrings{"gimlet-agent"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)), // Expired
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, _ := token.SignedString(privateKey)

	_, _, _, err := validator.ValidateAgentJWT(tokenString)
	if err == nil {
		t.Error("Expected error for expired token, got nil")
	}
}

func TestValidateAgentJWT_MissingService(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)
	validator := NewJWTValidator([]*rsa.PublicKey{publicKey}, "gimlet-test")

	claims := AgentClaims{
		Service: "", // Missing!
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "agent-1",
			Issuer:    "gimlet-test",
			Audience:  jwt.ClaimStrings{"gimlet-agent"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, _ := token.SignedString(privateKey)

	_, _, _, err := validator.ValidateAgentJWT(tokenString)
	if err == nil {
		t.Error("Expected error for missing service, got nil")
	}
}

func TestValidateClientJWT_Valid(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)
	validator := NewJWTValidator([]*rsa.PublicKey{publicKey}, "gimlet-test")

	claims := ClientClaims{
		Services: []string{"service-1", "service-2"},
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "client-1",
			Issuer:    "gimlet-test",
			Audience:  jwt.ClaimStrings{"gimlet-client"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, _ := token.SignedString(privateKey)

	clientID, services, expiresAt, err := validator.ValidateClientJWT(tokenString)
	if err != nil {
		t.Fatalf("Expected valid token, got error: %v", err)
	}

	if clientID != "client-1" {
		t.Errorf("Expected clientID 'client-1', got '%s'", clientID)
	}
	if len(services) != 2 {
		t.Errorf("Expected 2 services, got %d", len(services))
	}
	if expiresAt.IsZero() {
		t.Error("Expected non-zero expiry time")
	}
}

func TestValidateClientJWT_WrongAudience(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)
	validator := NewJWTValidator([]*rsa.PublicKey{publicKey}, "gimlet-test")

	claims := ClientClaims{
		Services: []string{"service-1"},
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "client-1",
			Issuer:    "gimlet-test",
			Audience:  jwt.ClaimStrings{"gimlet-agent"}, // Wrong!
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, _ := token.SignedString(privateKey)

	_, _, _, err := validator.ValidateClientJWT(tokenString)
	if err == nil {
		t.Error("Expected error for wrong audience, got nil")
	}
}

func TestValidateClientJWT_MissingServices(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)
	validator := NewJWTValidator([]*rsa.PublicKey{publicKey}, "gimlet-test")

	claims := ClientClaims{
		Services: []string{}, // Empty!
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "client-1",
			Issuer:    "gimlet-test",
			Audience:  jwt.ClaimStrings{"gimlet-client"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, _ := token.SignedString(privateKey)

	_, _, _, err := validator.ValidateClientJWT(tokenString)
	if err == nil {
		t.Error("Expected error for missing services, got nil")
	}
}

func TestValidateJWT_WrongSigningKey(t *testing.T) {
	privateKey1, _ := generateTestKeyPair(t)
	_, publicKey2 := generateTestKeyPair(t)

	// Sign with key1, validate with key2
	validator := NewJWTValidator([]*rsa.PublicKey{publicKey2}, "gimlet-test")

	claims := AgentClaims{
		Service: "test-service",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "agent-1",
			Issuer:    "gimlet-test",
			Audience:  jwt.ClaimStrings{"gimlet-agent"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, _ := token.SignedString(privateKey1)

	_, _, _, err := validator.ValidateAgentJWT(tokenString)
	if err == nil {
		t.Error("Expected error for wrong signing key, got nil")
	}
}

func TestSanitizeJWTError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: "",
		},
		{
			name:     "expired token",
			err:      jwt.ErrTokenExpired,
			expected: "Token expired",
		},
		{
			name:     "token not valid yet",
			err:      jwt.ErrTokenNotValidYet,
			expected: "Token not valid yet",
		},
		{
			name:     "malformed token",
			err:      jwt.ErrTokenMalformed,
			expected: "Token malformed",
		},
		{
			name:     "invalid signature",
			err:      jwt.ErrSignatureInvalid,
			expected: "Invalid signature",
		},
		{
			name:     "token signature invalid",
			err:      jwt.ErrTokenSignatureInvalid,
			expected: "Invalid signature",
		},
		{
			name:     "issuer mismatch - should be hidden",
			err:      fmt.Errorf("invalid issuer: expected gimlet, got evil"),
			expected: "Unauthorized",
		},
		{
			name:     "audience mismatch - should be hidden",
			err:      fmt.Errorf("invalid audience: expected gimlet-client"),
			expected: "Unauthorized",
		},
		{
			name:     "missing claims - should be hidden",
			err:      fmt.Errorf("missing sub claim (client ID)"),
			expected: "Unauthorized",
		},
		{
			name:     "unexpected signing method",
			err:      fmt.Errorf("unexpected signing method: HS256"),
			expected: "Unsupported signing method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeJWTError(tt.err)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestValidateJWT_MultipleKeys(t *testing.T) {
	// Test key rotation: validator has multiple keys, token signed with second key
	privateKey1, publicKey1 := generateTestKeyPair(t)
	privateKey2, publicKey2 := generateTestKeyPair(t)

	// Validator has both keys
	validator := NewJWTValidator([]*rsa.PublicKey{publicKey1, publicKey2}, "gimlet-test")

	// Token signed with first key should work
	claims1 := AgentClaims{
		Service: "test-service",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "agent-1",
			Issuer:    "gimlet-test",
			Audience:  jwt.ClaimStrings{"gimlet-agent"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}
	token1 := jwt.NewWithClaims(jwt.SigningMethodRS256, claims1)
	tokenString1, _ := token1.SignedString(privateKey1)

	agentID, _, _, err := validator.ValidateAgentJWT(tokenString1)
	if err != nil {
		t.Fatalf("Expected token signed with key1 to be valid, got error: %v", err)
	}
	if agentID != "agent-1" {
		t.Errorf("Expected agentID 'agent-1', got '%s'", agentID)
	}

	// Token signed with second key should also work
	claims2 := AgentClaims{
		Service: "test-service",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "agent-2",
			Issuer:    "gimlet-test",
			Audience:  jwt.ClaimStrings{"gimlet-agent"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}
	token2 := jwt.NewWithClaims(jwt.SigningMethodRS256, claims2)
	tokenString2, _ := token2.SignedString(privateKey2)

	agentID, _, _, err = validator.ValidateAgentJWT(tokenString2)
	if err != nil {
		t.Fatalf("Expected token signed with key2 to be valid, got error: %v", err)
	}
	if agentID != "agent-2" {
		t.Errorf("Expected agentID 'agent-2', got '%s'", agentID)
	}
}
