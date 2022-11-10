package apikey

import (
	"github.com/bancodobrasil/goauth"
	goauthgin "github.com/bancodobrasil/goauth-gin"
	"github.com/bancodobrasil/goauth/handler"
	"github.com/bancodobrasil/goauth/log"
	"github.com/gin-gonic/gin"
)

// Gin runs the example using Gin
func Gin(logger log.Logger) {
	log.SetLogger(logger)

	cfg := handler.VerifyAPIKeyConfig{
		Header: "X-API-Key",
		Key:    "123456",
	}
	h := []goauth.AuthHandler{
		handler.NewVerifyAPIKey(cfg),
	}
	goauth.SetHandlers(h)

	r := gin.Default()
	r.Use(goauthgin.Authenticate())
	r.GET("/ping", func(c *gin.Context) {
		log.Log(0, "pong")
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	r.Run()
}
