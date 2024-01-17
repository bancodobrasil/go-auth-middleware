package handler

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bancodobrasil/goauth/log"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// CacheConfig stores the configuration for the JWKS cache
type CacheConfig struct {
	// RefreshWindow is the time window before checking if the cache needs to be refreshed
	RefreshWindow time.Duration
	// MinRefreshInterval is the minimum interval between refreshes
	MinRefreshInterval time.Duration
	// Context is the context to use for the cache (see github.com/lestrrat-go/jwx/v2/jwk)
	Context context.Context
}

// VerifyJWKSConfig stores the configuration for the VerifyJWKS handler
type VerifyJWKSConfig struct {
	CacheConfig
	Header    string
	TokenType string
	// URL is the endpoint of the JWKS
	URL string
	// SignatureAlgorithm is the algorithm used to sign the JWT
	SignatureAlgorithm string
	// PayloadContextKey is the context key to store the JWT payload
	PayloadContextKey string
}

// VerifyJWKS stores the JWKS endpoint to be used for
// getting the signature key for JWT token verification
// and the cache for the signature key
type VerifyJWKS struct {
	header            string
	tokenType         string
	url               string
	ctx               context.Context
	signatureAlg      jwa.SignatureAlgorithm
	signatureKeyCache *jwk.Cache
	payloadContextKey string
}

// NewVerifyJWKS returns a new VerifyJWKS instance
func NewVerifyJWKS(cfg VerifyJWKSConfig) *VerifyJWKS {
	log.Log(log.Debug, "VerifyJWKS: NewVerifyJWKS")
	VerifyJWKS := &VerifyJWKS{
		header:            cfg.Header,
		tokenType:         cfg.TokenType,
		url:               cfg.URL,
		ctx:               cfg.Context,
		signatureAlg:      jwa.SignatureAlgorithm(cfg.SignatureAlgorithm),
		signatureKeyCache: jwk.NewCache(cfg.Context, jwk.WithRefreshWindow(cfg.RefreshWindow)),
		payloadContextKey: cfg.PayloadContextKey,
	}

	VerifyJWKS.setup(cfg)

	return VerifyJWKS
}

// setup sets up the signature key cache
func (m *VerifyJWKS) setup(cfg VerifyJWKSConfig) {
	m.signatureKeyCache.Register(m.url, jwk.WithMinRefreshInterval(cfg.MinRefreshInterval))
	_, err := m.signatureKeyCache.Refresh(m.ctx, m.url)
	if err != nil {
		log.Logf(log.Panic, "Failed to refresh JWKS: %s\n", err)
	}
}

// Handle runs the VerifyJWKS authentication handler
func (m *VerifyJWKS) Handle(r *http.Request) (request *http.Request, statusCode int, err error) {
	log.Log(log.Debug, "VerifyJWKS: Handle")
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

	key, statusCode, err := m.getSignatureKey(m.ctx)
	if err != nil {
		log.Log(log.Error, err)
		return r, statusCode, err
	}

	verified, internalErr := jws.Verify([]byte(token), jws.WithKey(m.signatureAlg, key))
	if internalErr != nil {
		return r, defaultStatusCode, invalidJWTError
	}

	if !bytes.Equal(verified, msg.Payload()) {
		return r, defaultStatusCode, invalidJWTError
	}

	log.Log(log.Debug, "claims: ", string(msg.Payload()))
	log.Log(log.Debug, "ctx: ", m.payloadContextKey)
	c := context.WithValue(r.Context(), m.payloadContextKey, string(msg.Payload()))

	return r.WithContext(c), 0, nil
}

func (m *VerifyJWKS) extractTokenFromHeader(h *http.Header) (string, int, error) {
	authorizationHeader := h.Get(m.header)
	if authorizationHeader == "" {
		return "", 401, errors.New(fmt.Sprintf("Missing %s Header", m.header))
	}
	if m.tokenType == "" {
		return authorizationHeader, 0, nil
	}
	splitHeader := strings.Split(authorizationHeader, "Bearer")
	if len(splitHeader) != 2 {
		return "", 401, errors.New(fmt.Sprintf("Invalid %s Header", m.header))
	}
	return strings.TrimSpace(splitHeader[1]), 0, nil
}

func (m *VerifyJWKS) getSignatureKey(ctx context.Context) (jwk.Key, int, error) {
	keyset, err := m.signatureKeyCache.Get(m.ctx, m.url)
	errorMsg := "Failed to fetch JWKS"
	if err != nil {
		log.Logf(log.Error, "%s: %s\n", errorMsg, err)
		return nil, 502, errors.New(errorMsg)
	}

	idx := 0
	key, exists := keyset.Key(idx)

	// TODO: Reimplement this logic to support other algorithms
	if exists && key.Algorithm() == m.signatureAlg {
		return key, 0, nil
	} else {
		exists = false
	}

	for !exists {
		idx++
		key, exists = keyset.Key(idx)
		if exists && key.Algorithm() == m.signatureAlg {
			return key, 0, nil
		}
		if !keyset.Keys(ctx).Next(ctx) {
			errorMsg := fmt.Sprintf("No valid JWK found for algorithm %s", m.signatureAlg)
			return nil, 502, errors.New(errorMsg)
		}
	}

	return nil, 502, errors.New(errorMsg)
}
