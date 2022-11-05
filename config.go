package goauth

import (
	"strings"
	"time"

	"github.com/bancodobrasil/goauth/handler"
	"github.com/spf13/viper"
)

// Config stores the configuration for the Goauth middleware
type Config struct {
	// AuthHandlers is the list of authentication handlers to be used
	AuthHandlers string `mapstructure:"GOAUTH_AUTH_HANDLERS"`

	// ApiKey is the API key to be used on the VerifyAPIKey handler
	ApiKey       string `mapstructure:"GOAUTH_API_KEY"`
	ApiKeyHeader string `mapstructure:"GOAUTH_API_KEY_HEADER"`

	// JwksUrl is the JWKS endpoint to be used on the VerifyJWKS handler
	JwksUrl string `mapstructure:"GOAUTH_JWKS_URL"`
	// JwksRefreshWindow is the time window before checking if the JWKS cache needs to be refreshed
	JwksRefreshWindow int `mapstructure:"GOAUTH_JWKS_REFRESH_WINDOW"`
	// JwksMinRefreshInterval is the minimum interval between JWKS refreshes
	JwksMinRefreshInterval int `mapstructure:"GOAUTH_JWKS_MIN_REFRESH_INTERVAL"`

	// JwtSignatureKey is the signature key to be used on the VerifyJWT handler
	JwtSignatureKey string `mapstructure:"GOAUTH_JWT_SIGNATURE_KEY"`
}

var config = &Config{}

// LoadConfig loads the configuration from the environment variables
func loadConfig() {
	viper.AutomaticEnv()

	viper.SetDefault("GOAUTH_AUTH_HANDLERS", "")
	viper.SetDefault("GOAUTH_API_KEY", "")
	viper.SetDefault("GOAUTH_API_KEY_HEADER", "X-API-Key")
	viper.SetDefault("GOAUTH_JWKS_URL", "")
	viper.SetDefault("GOAUTH_JWKS_REFRESH_WINDOW", 1*time.Minute)
	viper.SetDefault("GOAUTH_JWKS_MIN_REFRESH_INTERVAL", 5*time.Minute)
	viper.SetDefault("GOAUTH_JWT_SIGNATURE_KEY", "")

	viper.Unmarshal(config)
}

// BootstrapMiddleware sets up the authentication handlers
func BootstrapMiddleware() {
	loadConfig()
	if config.AuthHandlers == "" {
		return
	}
	authHandlers := strings.Split(config.AuthHandlers, ",")
	handlers := make([]AuthHandler, len(authHandlers))
	for _, h := range authHandlers {
		switch strings.ToLower(h) {
		case "api_key":
			if config.ApiKey == "" {
				panic("GOAUTH_API_KEY is required when using the API Key handler")
			}
			cfg := handler.VerifyAPIKeyConfig{
				Header: config.ApiKeyHeader,
				Key:    config.ApiKey,
			}
			handlers = append(handlers, handler.NewVerifyAPIKey(cfg))
		case "jwks":
			if config.JwksUrl == "" {
				panic("GOAUTH_JWKS_URL is required when using the JWKS handler")
			}
			cfg := handler.VerifyJWKSConfig{
				URL:         config.JwksUrl,
				CacheConfig: handler.CacheConfig{RefreshWindow: time.Duration(config.JwksRefreshWindow), MinRefreshInterval: time.Duration(config.JwksMinRefreshInterval)},
			}
			handlers = append(handlers, handler.NewVerifyJWKS(cfg))
		case "jwt":
			if config.JwtSignatureKey == "" {
				panic("GOAUTH_JWT_SIGNATURE_KEY is required when using the JWT handler")
			}
			cfg := handler.VerifyJWTConfig{
				SignatureKey: config.JwtSignatureKey,
			}
			handlers = append(handlers, handler.NewVerifyJWT(cfg))
		}
	}
	SetHandlers(handlers)
}
