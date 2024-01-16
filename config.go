package goauth

import (
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
	// URL is the JWKS endpoint to be used on the VerifyJWKS handler
	URL string `mapstructure:"GOAUTH_JWKS_URL"`
	// RefreshWindow is the time window before checking if the JWKS cache needs to be refreshed, in seconds. Defaults to 60
	RefreshWindow int `mapstructure:"GOAUTH_JWKS_REFRESH_WINDOW"`
	// MinRefreshInterval is the minimum interval between JWKS refreshes, in seconds. Defaults to 300
	MinRefreshInterval int `mapstructure:"GOAUTH_JWKS_MIN_REFRESH_INTERVAL"`
}

// JWTConfig is the config to be used on the VerifyJWT handler
type JWTConfig struct {
	// Header is the header to be used on the VerifyJWT handler. Defaults to Authorization
	Header string `mapstructure:"GOAUTH_JWT_HEADER"`
	// SignatureKey is the signature key to be used on the VerifyJWT handler
	SignatureKey string `mapstructure:"GOAUTH_JWT_SIGNATURE_KEY"`
	// PayloadContextKey is the context key to store the JWT payload. Defaults to JWT_PAYLOAD
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

	viper.SetDefault("GOAUTH_HANDLERS", "")
	viper.SetDefault("GOAUTH_API_KEY_HEADER", "X-API-Key")
	viper.SetDefault("GOAUTH_API_KEY_LIST", []string{})
	viper.SetDefault("GOAUTH_JWKS_HEADER", "Authorization")
	viper.SetDefault("GOAUTH_JWKS_URL", "")
	viper.SetDefault("GOAUTH_JWKS_REFRESH_WINDOW", 1*time.Minute)
	viper.SetDefault("GOAUTH_JWKS_MIN_REFRESH_INTERVAL", 5*time.Minute)
	viper.SetDefault("GOAUTH_JWT_HEADER", "Authorization")
	viper.SetDefault("GOAUTH_JWT_SIGNATURE_KEY", "")
	viper.SetDefault("GOAUTH_JWT_PAYLOAD_CONTEXT_KEY", "JWT_PAYLOAD")

	viper.Unmarshal(config)
}

// BootstrapMiddleware sets up the authentication handlers
func BootstrapMiddleware() {
	log.Log(0, "BootstrapMiddleware")
	loadConfig()
	if len(config.Handlers) == 0 {
		return
	}
	log.Logf(1, "Handlers: %s", config.Handlers)
	handlers := []AuthHandler{}
	for _, h := range config.Handlers {
		switch strings.ToLower(h) {
		case "api_key":
			if len(config.APIKeyConfig.KeyList) == 0 {
				panic("GOAUTH_API_KEY_LIST is required when using the API Key handler")
			}
			cfg := handler.VerifyAPIKeyConfig{
				Header: config.APIKeyConfig.Header,
				Keys:   config.APIKeyConfig.KeyList,
			}
			handlers = append(handlers, handler.NewVerifyAPIKey(cfg))
			log.Log(1, "Using API Key authentication")
		case "jwks":
			if config.JWKSConfig.URL == "" {
				panic("GOAUTH_JWKS_URL is required when using the JWKS handler")
			}
			cfg := handler.VerifyJWKSConfig{
				URL:         config.JWKSConfig.URL,
				CacheConfig: handler.CacheConfig{RefreshWindow: time.Duration(config.JWKSConfig.RefreshWindow), MinRefreshInterval: time.Duration(config.JWKSConfig.MinRefreshInterval)},
			}
			handlers = append(handlers, handler.NewVerifyJWKS(cfg))
			log.Log(1, "Using JWKS authentication")
		case "jwt":
			if config.JWTConfig.SignatureKey == "" {
				panic("GOAUTH_JWT_SIGNATURE_KEY is required when using the JWT handler")
			}
			cfg := handler.VerifyJWTConfig{
				SignatureKey: config.JWTConfig.SignatureKey,
			}
			handlers = append(handlers, handler.NewVerifyJWT(cfg))
			log.Log(1, "Using JWT authentication")
		}
	}
	SetHandlers(handlers)
}
