package main

import (
	goauth "github.com/bancodobrasil/go-auth-middleware"
	"github.com/bancodobrasil/go-auth-middleware/handler"
	"github.com/gin-gonic/gin"
)

// RunGinExample runs the example using Gin
func RunGinExample() {
	r := gin.Default()
	cfg := handler.VerifyAPIKeyConfig{
		Header: "X-API-Key",
		Key:    "123456",
	}
	h := []goauth.AuthHandler{
		handler.NewVerifyAPIKey(cfg),
	}
	goauth.SetHandlers(h)
	r.Use(gin.WrapH(goauth.Authenticate(nil)))
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	r.Run()
}
