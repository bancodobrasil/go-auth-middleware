package goauth

import (
	"context"
	"strings"
	"time"

	"github.com/bancodobrasil/goauth/handler"
	"github.com/bancodobrasil/goauth/log"
	"github.com/spf13/viper"
)

// APIKeyConfig is the config to be used on the VerifyAPIKey handler
type APIKeyConfig struct {
	// Header is the header to be used on the VerifyAPIKey handler. Defaults to X-API-Key
	Header string `mapstructure:"GOAUTH_API_KEY_HEADER"`
	// KeyList is the list of API keys to be used on the VerifyAPIKey handler, separated by comma
	KeyList []string `mapstructure:"GOAUTH_API_KEY_LIST"`
}

// JWKSConfig is the config to be used on the VerifyJWKS handler
type JWKSConfig struct {
	// Header is the header to be used on the VerifyJWKS handler. Defaults to Authorization
	Header string `mapstructure:"GOAUTH_JWKS_HEADER"`
	// TokenType is the token type to be used on the VerifyJWKS handler. Defaults to Bearer
	TokenType string `mapstructure:"GOAUTH_JWKS_TOKEN_TYPE"`
	// URL is the JWKS endpoint to be used on the VerifyJWKS handler
	URL string `mapstructure:"GOAUTH_JWKS_URL"`
	// RefreshWindow is the time window before checking if the JWKS cache needs to be refreshed, in seconds. Defaults to 60
	RefreshWindow int `mapstructure:"GOAUTH_JWKS_REFRESH_WINDOW"`
	// MinRefreshInterval is the minimum interval between JWKS refreshes, in seconds. Defaults to 300
	MinRefreshInterval int `mapstructure:"GOAUTH_JWKS_MIN_REFRESH_INTERVAL"`
	// PayloadContextKey is the context key to store the JWT payload. Defaults to USER
	PayloadContextKey string `mapstructure:"GOAUTH_JWKS_PAYLOAD_CONTEXT_KEY"`
}

// JWTConfig is the config to be used on the VerifyJWT handler
type JWTConfig struct {
	// Header is the header to be used on the VerifyJWT handler. Defaults to Authorization
	Header string `mapstructure:"GOAUTH_JWT_HEADER"`
	// TokenType is the token type to be used on the VerifyJWT handler. Defaults to Bearer
	TokenType string `mapstructure:"GOAUTH_JWT_TOKEN_TYPE"`
	// SignatureKey is the signature key to be used on the VerifyJWT handler
	SignatureKey string `mapstructure:"GOAUTH_JWT_SIGNATURE_KEY"`
	// SignatureAlgorithm is the algorithm used to sign the JWT. Defaults to RS256
	SignatureAlgorithm string `mapstructure:"GOAUTH_JWT_SIGNATURE_ALGORITHM"`
	// PayloadContextKey is the context key to store the JWT payload. Defaults to USER
	PayloadContextKey string `mapstructure:"GOAUTH_JWT_PAYLOAD_CONTEXT_KEY"`
}

// Config stores the configuration for the Goauth middleware
type Config struct {
	// AuthHandlers is the list of authentication handlers to be used
	Handlers []string `mapstructure:"GOAUTH_HANDLERS"`

	// APIKeyConfig stores the configuration for the VerifyAPIKey handler
	APIKeyConfig APIKeyConfig `mapstructure:",squash"`

	// JWKSConfig stores the configuration for the VerifyJWKS handler
	JWKSConfig JWKSConfig `mapstructure:",squash"`

	// JWTConfig stores the configuration for the VerifyJWT handler
	JWTConfig JWTConfig `mapstructure:",squash"`
}

var config = &Config{}

// LoadConfig loads the configuration from the environment variables
func loadConfig() {
	viper.AutomaticEnv()

	viper.SetDefault("GOAUTH_HANDLERS", []string{})
	viper.SetDefault("GOAUTH_API_KEY_HEADER", "X-API-Key")
	viper.SetDefault("GOAUTH_API_KEY_LIST", []string{})
	viper.SetDefault("GOAUTH_JWKS_HEADER", "Authorization")
	viper.SetDefault("GOAUTH_JWKS_TOKEN_TYPE", "Bearer")
	viper.SetDefault("GOAUTH_JWKS_URL", "")
	viper.SetDefault("GOAUTH_JWKS_REFRESH_WINDOW", 1*time.Minute)
	viper.SetDefault("GOAUTH_JWKS_MIN_REFRESH_INTERVAL", 5*time.Minute)
	viper.SetDefault("GOAUTH_JWKS_SIGNATURE_ALGORITHM", "RS256")
	viper.SetDefault("GOAUTH_JWKS_PAYLOAD_CONTEXT_KEY", "USER")
	viper.SetDefault("GOAUTH_JWT_HEADER", "Authorization")
	viper.SetDefault("GOAUTH_JWT_TOKEN_TYPE", "Bearer")
	viper.SetDefault("GOAUTH_JWT_SIGNATURE_KEY", "")
	viper.SetDefault("GOAUTH_JWT_SIGNATURE_ALGORITHM", "RS256")
	viper.SetDefault("GOAUTH_JWT_PAYLOAD_CONTEXT_KEY", "USER")

	viper.Unmarshal(config)
}

// BootstrapMiddleware sets up the authentication handlers.
// The context object is used to controll the life-cycle
// of the JWKS cache auto-refresh worker.
func BootstrapMiddleware(ctx context.Context) {
	log.Log(log.Debug, "BootstrapMiddleware")
	loadConfig()
	if len(config.Handlers) == 0 {
		return
	}
	log.Logf(log.Info, "Handlers: %s", config.Handlers)
	handlers := []AuthHandler{}
	for _, h := range config.Handlers {
		switch strings.ToLower(h) {
		case "api_key":
			if len(config.APIKeyConfig.KeyList) == 0 {
				log.Log(log.Panic, "GOAUTH_API_KEY_LIST is required when using the API Key handler")
			}
			cfg := handler.VerifyAPIKeyConfig{
				Header: config.APIKeyConfig.Header,
				Keys:   config.APIKeyConfig.KeyList,
			}
			handlers = append(handlers, handler.NewVerifyAPIKey(cfg))
			log.Log(log.Info, "Using API Key authentication")
		case "jwks":
			if config.JWKSConfig.URL == "" {
				log.Log(log.Panic, "GOAUTH_JWKS_URL is required when using the JWKS handler")
			}
			cfg := handler.VerifyJWKSConfig{
				Header:    config.JWKSConfig.Header,
				TokenType: config.JWKSConfig.TokenType,
				URL:       config.JWKSConfig.URL,
				CacheConfig: handler.CacheConfig{
					RefreshWindow:      time.Duration(config.JWKSConfig.RefreshWindow),
					MinRefreshInterval: time.Duration(config.JWKSConfig.MinRefreshInterval),
					Context:            ctx,
				},
			}
			handlers = append(handlers, handler.NewVerifyJWKS(cfg))
			log.Log(log.Info, "Using JWKS authentication")
		case "jwt":
			if config.JWTConfig.SignatureKey == "" {
				log.Log(log.Panic, "GOAUTH_JWT_SIGNATURE_KEY is required when using the JWT handler")
			}
			cfg := handler.VerifyJWTConfig{
				Header:             config.JWTConfig.Header,
				TokenType:          config.JWTConfig.TokenType,
				SignatureKey:       config.JWTConfig.SignatureKey,
				SignatureAlgorithm: config.JWTConfig.SignatureAlgorithm,
				PayloadContextKey:  config.JWTConfig.PayloadContextKey,
			}
			handlers = append(handlers, handler.NewVerifyJWT(cfg))
			log.Log(log.Info, "Using JWT authentication")
		}
	}
	SetHandlers(handlers)
}
