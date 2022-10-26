package handler

import (
	"errors"
	"fmt"
	"net/http"
)

// VerifyAPIKeyConfig stores the configuration for the VerifyAPIKey handler
type VerifyAPIKeyConfig struct {
	Header string
	Key    string
}

// VerifyAPIKey stores the Header and the API key to be used for authentication
type VerifyAPIKey struct {
	header string
	key    string
}

// NewVerifyAPIKey returns a new VerifyAPIKey instance
func NewVerifyAPIKey(cfg VerifyAPIKeyConfig) *VerifyAPIKey {
	return &VerifyAPIKey{
		header: cfg.Header,
		key:    cfg.Key,
	}

}

// Authenticate runs the authentication handler
func (a *VerifyAPIKey) Authenticate(h *http.Header) (statusCode int, err error) {
	key, statusCode, err := a.extractKeyFromHeader(h)
	if err != nil {
		return statusCode, err
	}

	if key != a.key {
		return 401, errors.New("Unauthorized")
	}

	return 0, nil
}

func (a *VerifyAPIKey) extractKeyFromHeader(h *http.Header) (key string, statusCode int, err error) {
	authorizationHeader := h.Get(a.header)
	if authorizationHeader == "" {
		return "", 401, errors.New(fmt.Sprintf("Missing %s Header", a.header))
	}
	return authorizationHeader, 0, nil
}
