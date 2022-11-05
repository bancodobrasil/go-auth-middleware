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

// Handle runs the VerifyAPIKey authentication handler
func (a *VerifyAPIKey) Handle(r *http.Request) (request *http.Request, statusCode int, err error) {
	key, statusCode, err := a.extractKeyFromHeader(&r.Header)
	if err != nil {
		return r, statusCode, err
	}

	if key != a.key {
		return r, 401, errors.New("Unauthorized")
	}

	return r, 0, nil
}

func (a *VerifyAPIKey) extractKeyFromHeader(h *http.Header) (key string, statusCode int, err error) {
	authorizationHeader := h.Get(a.header)
	if authorizationHeader == "" {
		return "", 401, fmt.Errorf("Missing %s Header", a.header)
	}
	return authorizationHeader, 0, nil
}
