package goauth

import (
	"time"

	"github.com/spf13/viper"
)

// Config stores the configuration for the Goauth middleware
type Config struct {
	// AuthHandlers is the list of authentication handlers to be used
	AuthHandlers string `mapstructure:"GOAUTH_AUTH_HANDLERS"`

	// ApiKey is the API key to be used on the VerifyAPIKey handler
	ApiKey string `mapstructure:"GOAUTH_API_KEY"`

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
func LoadConfig() {
	viper.AutomaticEnv()

	viper.SetDefault("GOAUTH_AUTH_HANDLERS", "")
	viper.SetDefault("GOAUTH_API_KEY", "")
	viper.SetDefault("GOAUTH_JWKS_URL", "")
	viper.SetDefault("GOAUTH_JWKS_REFRESH_WINDOW", 1*time.Minute)
	viper.SetDefault("GOAUTH_JWKS_MIN_REFRESH_INTERVAL", 5*time.Minute)
	viper.SetDefault("GOAUTH_JWT_SIGNATURE_KEY", "")

	viper.Unmarshal(config)
}
