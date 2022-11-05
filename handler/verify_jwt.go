package handler

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/bancodobrasil/goauth/log"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// JWTPayloadContextKey is the context key to store the JWT payload
type JWTPayloadContextKey string

// VerifyJWTConfig stores the configuration for the VerifyJWT handler
type VerifyJWTConfig struct {
	SignatureKey      string
	PayloadContextKey JWTPayloadContextKey
}

// VerifyJWT stores the JWKS signature key
type VerifyJWT struct {
	signatureKey      jwk.Key
	payloadContextKey JWTPayloadContextKey
}

// NewVerifyJWT returns a new VerifyJWT instance
func NewVerifyJWT(cfg VerifyJWTConfig) *VerifyJWT {
	log.Log(0, "VerifyJWT: NewVerifyJWT")
	key, err := jwk.FromRaw([]byte(cfg.SignatureKey))
	if err != nil {
		log.Log(5, err)
		return nil
	}
	VerifyJWT := &VerifyJWT{
		signatureKey:      key,
		payloadContextKey: cfg.PayloadContextKey,
	}

	return VerifyJWT
}

// Handle runs the VerifyJWT authentication handler
func (m *VerifyJWT) Handle(r *http.Request) (request *http.Request, statusCode int, err error) {
	log.Log(0, "VerifyJWT: Handle")
	token, statusCode, err := m.extractTokenFromHeader(&r.Header)
	if err != nil {
		return r, statusCode, err
	}

	invalidJWTError := errors.New("Invalid JWT token")
	defaultStatusCode := 401

	msg, internalErr := jws.Parse([]byte(token))
	if internalErr != nil {
		log.Log(3, internalErr)
		return r, defaultStatusCode, invalidJWTError
	}

	verified, internalErr := jws.Verify([]byte(token), jws.WithKey(jwa.HS256, m.signatureKey))
	if internalErr != nil {
		log.Log(3, internalErr)
		return r, defaultStatusCode, invalidJWTError
	}

	if !bytes.Equal(verified, msg.Payload()) {
		return r, defaultStatusCode, invalidJWTError
	}

	ctx := context.WithValue(r.Context(), m.payloadContextKey, string(msg.Payload()))

	return r.WithContext(ctx), 0, nil
}

func (m *VerifyJWT) extractTokenFromHeader(h *http.Header) (string, int, error) {
	authorizationHeader := h.Get("Authorization")
	if authorizationHeader == "" {
		return "", 401, errors.New("Missing Authorization Header")
	}
	splitHeader := strings.Split(authorizationHeader, "Bearer")
	if len(splitHeader) != 2 {
		return "", 401, errors.New("Invalid Authorization Header")
	}
	return strings.TrimSpace(splitHeader[1]), 0, nil
}
