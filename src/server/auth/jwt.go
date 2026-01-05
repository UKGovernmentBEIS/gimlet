package auth

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SanitizeJWTError returns a client-safe error message.
// Token-related issues (expired, invalid signature) are returned.
// System config issues (issuer, audience, claims structure) are hidden.
func SanitizeJWTError(err error) string {
	if err == nil {
		return ""
	}

	// Check for JWT library errors that are safe to expose
	if errors.Is(err, jwt.ErrTokenExpired) {
		return "Token expired"
	}
	if errors.Is(err, jwt.ErrTokenNotValidYet) {
		return "Token not valid yet"
	}
	if errors.Is(err, jwt.ErrTokenMalformed) {
		return "Token malformed"
	}
	if errors.Is(err, jwt.ErrSignatureInvalid) {
		return "Invalid signature"
	}
	if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		return "Invalid signature"
	}

	// Check for our own safe-to-expose errors
	errStr := err.Error()
	if strings.Contains(errStr, "unexpected signing method") {
		return "Unsupported signing method"
	}

	// Default: hide system config details
	return "Unauthorized"
}

type AgentClaims struct {
	Service string `json:"service"`
	jwt.RegisteredClaims
}

type ClientClaims struct {
	Services []string `json:"services"`
	jwt.RegisteredClaims
}

type JWTValidator struct {
	publicKeys []*rsa.PublicKey
	issuer     string
}

// NewJWTValidator creates a new JWT validator with one or more public keys.
// Multiple keys support key rotation - tokens signed with any key are valid.
func NewJWTValidator(publicKeys []*rsa.PublicKey, issuer string) *JWTValidator {
	return &JWTValidator{
		publicKeys: publicKeys,
		issuer:     issuer,
	}
}

// ValidateAgentJWT validates a JWT for agent registration (aud: gimlet-agent)
// Returns (agentID, service, expiresAt, error)
func (v *JWTValidator) ValidateAgentJWT(tokenString string) (string, string, time.Time, error) {
	var lastErr error

	// Try each public key
	for _, publicKey := range v.publicKeys {
		token, err := jwt.ParseWithClaims(tokenString, &AgentClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return publicKey, nil
		})

		if err != nil {
			lastErr = err
			continue
		}

		claims, ok := token.Claims.(*AgentClaims)
		if !ok || !token.Valid {
			lastErr = fmt.Errorf("invalid token claims")
			continue
		}

		// Validate required fields
		if claims.Issuer != v.issuer {
			return "", "", time.Time{}, fmt.Errorf("invalid issuer: expected %s, got %s", v.issuer, claims.Issuer)
		}

		audience, err := claims.GetAudience()
		if err != nil || len(audience) != 1 || audience[0] != "gimlet-agent" {
			return "", "", time.Time{}, fmt.Errorf("invalid audience: expected gimlet-agent")
		}

		if claims.Subject == "" {
			return "", "", time.Time{}, fmt.Errorf("missing sub claim (agent ID)")
		}

		if claims.Service == "" {
			return "", "", time.Time{}, fmt.Errorf("missing service claim")
		}

		expiresAt, err := claims.GetExpirationTime()
		if err != nil {
			return "", "", time.Time{}, fmt.Errorf("invalid exp claim: %w", err)
		}

		return claims.Subject, claims.Service, expiresAt.Time, nil
	}

	return "", "", time.Time{}, fmt.Errorf("invalid token: %w", lastErr)
}

// ValidateClientJWT validates a JWT for client requests (aud: gimlet-client)
// Returns (clientID, services, expiresAt, error)
func (v *JWTValidator) ValidateClientJWT(tokenString string) (string, []string, time.Time, error) {
	var lastErr error

	// Try each public key
	for _, publicKey := range v.publicKeys {
		token, err := jwt.ParseWithClaims(tokenString, &ClientClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return publicKey, nil
		})

		if err != nil {
			lastErr = err
			continue
		}

		claims, ok := token.Claims.(*ClientClaims)
		if !ok || !token.Valid {
			lastErr = fmt.Errorf("invalid token claims")
			continue
		}

		// Validate required fields
		if claims.Issuer != v.issuer {
			return "", nil, time.Time{}, fmt.Errorf("invalid issuer: expected %s, got %s", v.issuer, claims.Issuer)
		}

		audience, err := claims.GetAudience()
		if err != nil || len(audience) != 1 || audience[0] != "gimlet-client" {
			return "", nil, time.Time{}, fmt.Errorf("invalid audience: expected gimlet-client")
		}

		if claims.Subject == "" {
			return "", nil, time.Time{}, fmt.Errorf("missing sub claim (client ID)")
		}

		if len(claims.Services) == 0 {
			return "", nil, time.Time{}, fmt.Errorf("missing services claim")
		}

		expiresAt, err := claims.GetExpirationTime()
		if err != nil {
			return "", nil, time.Time{}, fmt.Errorf("invalid exp claim: %w", err)
		}

		return claims.Subject, claims.Services, expiresAt.Time, nil
	}

	return "", nil, time.Time{}, fmt.Errorf("invalid token: %w", lastErr)
}
