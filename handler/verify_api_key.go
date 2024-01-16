package handler

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/bancodobrasil/goauth/log"
)

// VerifyAPIKeyConfig stores the configuration for the VerifyAPIKey handler
type VerifyAPIKeyConfig struct {
	Header string
	Keys   []string
}

// VerifyAPIKey stores the Header and the API key to be used for authentication
type VerifyAPIKey struct {
	header string
	keys   []string
}

// NewVerifyAPIKey returns a new VerifyAPIKey instance
func NewVerifyAPIKey(cfg VerifyAPIKeyConfig) *VerifyAPIKey {
	log.Logf(0, "NewVerifyAPIKey: %v", cfg)
	return &VerifyAPIKey{
		header: cfg.Header,
		keys:   cfg.Keys,
	}

}

// Handle runs the VerifyAPIKey authentication handler
func (a *VerifyAPIKey) Handle(r *http.Request) (request *http.Request, statusCode int, err error) {
	log.Log(0, "VerifyAPIKey: Handle")
	key, statusCode, err := a.extractKeyFromHeader(&r.Header)
	if err != nil {
		return r, statusCode, err
	}

	for _, k := range a.keys {
		if key == k {
			return r, 0, nil
		}
	}

	return r, 401, errors.New("Unauthorized")
}

func (a *VerifyAPIKey) extractKeyFromHeader(h *http.Header) (key string, statusCode int, err error) {
	authorizationHeader := h.Get(a.header)
	if authorizationHeader == "" {
		return "", 401, fmt.Errorf("Missing %s Header", a.header)
	}
	return authorizationHeader, 0, nil
}
