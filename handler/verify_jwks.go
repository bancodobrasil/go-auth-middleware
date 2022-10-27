package handler

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/bancodobrasil/go-auth-middleware/log"
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
	// URL is the endpoint of the JWKS
	URL string
}

// VerifyJWKS stores the JWKS endpoint to be used for
// getting the signature key for JWT token verification
// and the cache for the signature key
type VerifyJWKS struct {
	url               string
	ctx               context.Context
	signatureKeyCache *jwk.Cache
}

// NewVerifyJWKS returns a new VerifyJWKS instance
func NewVerifyJWKS(cfg VerifyJWKSConfig) *VerifyJWKS {
	VerifyJWKS := &VerifyJWKS{
		url:               cfg.URL,
		ctx:               cfg.Context,
		signatureKeyCache: jwk.NewCache(cfg.Context, jwk.WithRefreshWindow(cfg.RefreshWindow)),
	}

	VerifyJWKS.setup(cfg)

	return VerifyJWKS
}

// setup sets up the signature key cache
func (m *VerifyJWKS) setup(cfg VerifyJWKSConfig) {
	log.Log(0, "Initializing VerifyJWKS")
	m.signatureKeyCache.Register(m.url, jwk.WithMinRefreshInterval(cfg.MinRefreshInterval))
	_, err := m.signatureKeyCache.Refresh(m.ctx, m.url)
	if err != nil {
		log.Logf(5, "Failed to refresh JWKS: %s\n", err)
	}
}

// Handle runs the VerifyJWKS authentication handler
func (m *VerifyJWKS) Handle(h *http.Header) (statusCode int, err error) {
	token, statusCode, err := m.extractTokenFromHeader(h)
	if err != nil {
		return statusCode, err
	}

	invalidJWTError := errors.New("Invalid JWT token")
	defaultStatusCode := 401

	msg, internalErr := jws.Parse([]byte(token))
	if internalErr != nil {
		return defaultStatusCode, invalidJWTError
	}

	key, statusCode, err := m.getSignatureKey()
	if err != nil {
		return statusCode, err
	}

	verified, internalErr := jws.Verify([]byte(token), jws.WithKey(jwa.RS256, key))
	if internalErr != nil {
		return defaultStatusCode, invalidJWTError
	}

	if !bytes.Equal(verified, msg.Payload()) {
		return defaultStatusCode, invalidJWTError
	}

	return 0, nil
}

func (m *VerifyJWKS) extractTokenFromHeader(h *http.Header) (string, int, error) {
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
func (m *VerifyJWKS) getSignatureKey() (jwk.Key, int, error) {
	keyset, err := m.signatureKeyCache.Get(m.ctx, m.url)
	errorMsg := "Failed to fetch JWKS"
	if err != nil {
		log.Logf(3, "%s: %s\n", errorMsg, err)
		return nil, 502, errors.New(errorMsg)
	}
	key, exists := keyset.Key(0)
	if !exists {
		log.Logf(3, "%s: %s\n", errorMsg, err)
		return nil, 502, errors.New(errorMsg)
	}
	return key, 0, nil
}
