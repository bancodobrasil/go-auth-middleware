package handler

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/bancodobrasil/goauth/log"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// VerifyJWTConfig stores the configuration for the VerifyJWT handler
type VerifyJWTConfig struct {
	Header             string
	TokenType          string
	SignatureKey       string
	SignatureAlgorithm string
	PayloadContextKey  string
}

// VerifyJWT stores the JWKS signature key
type VerifyJWT struct {
	header            string
	tokenType         string
	signatureKey      jwk.Key
	signatureAlg      jwa.SignatureAlgorithm
	payloadContextKey string
}

// NewVerifyJWT returns a new VerifyJWT instance
func NewVerifyJWT(cfg VerifyJWTConfig) *VerifyJWT {
	log.Log(log.Debug, "VerifyJWT: NewVerifyJWT")
	key, err := jwk.FromRaw([]byte(cfg.SignatureKey))
	if err != nil {
		log.Log(log.Panic, err)
		return nil
	}
	VerifyJWT := &VerifyJWT{
		header:            cfg.Header,
		tokenType:         cfg.TokenType,
		signatureAlg:      jwa.SignatureAlgorithm(cfg.SignatureAlgorithm),
		signatureKey:      key,
		payloadContextKey: cfg.PayloadContextKey,
	}

	return VerifyJWT
}

// Handle runs the VerifyJWT authentication handler
func (m *VerifyJWT) Handle(r *http.Request) (request *http.Request, statusCode int, err error) {
	log.Log(log.Debug, "VerifyJWT: Handle")
	token, statusCode, err := m.extractTokenFromHeader(&r.Header)
	if err != nil {
		return r, statusCode, err
	}

	invalidJWTError := errors.New("Invalid JWT token")
	defaultStatusCode := 401

	msg, internalErr := jws.Parse([]byte(token))
	if internalErr != nil {
		log.Log(log.Error, internalErr)
		return r, defaultStatusCode, invalidJWTError
	}

	verified, internalErr := jws.Verify([]byte(token), jws.WithKey(m.signatureAlg, m.signatureKey))
	if internalErr != nil {
		log.Log(log.Error, internalErr)
		return r, defaultStatusCode, invalidJWTError
	}

	if !bytes.Equal(verified, msg.Payload()) {
		return r, defaultStatusCode, invalidJWTError
	}

	_, parseErr := jwt.Parse(msg.Payload(), jwt.WithVerify(false))
	if parseErr != nil {
		log.Log(log.Error, parseErr)
		return r, defaultStatusCode, invalidJWTError
	}

	ctx := context.WithValue(r.Context(), m.payloadContextKey, string(msg.Payload()))

	return r.WithContext(ctx), 0, nil
}

func (m *VerifyJWT) extractTokenFromHeader(h *http.Header) (string, int, error) {
	authorizationHeader := h.Get(m.header)
	if authorizationHeader == "" {
		return "", 401, errors.New(fmt.Sprintf("Missing %s Header", m.header))
	}
	if m.tokenType == "" {
		return authorizationHeader, 0, nil
	}
	splitHeader := strings.Split(authorizationHeader, m.tokenType)
	if len(splitHeader) != 2 {
		return "", 401, errors.New(fmt.Sprintf("Invalid %s Header", m.header))
	}
	return strings.TrimSpace(splitHeader[1]), 0, nil
}
