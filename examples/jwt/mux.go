package jwt

import (
	"net/http"

	"github.com/bancodobrasil/goauth"
	"github.com/bancodobrasil/goauth/handler"
	"github.com/bancodobrasil/goauth/log"
	"github.com/gorilla/mux"
)

// Mux runs the example using Gorilla Mux
func Mux(logger log.Logger) {
	// Example JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.keH6T3x1z7mmhKL1T3r9sQdAxxdzB6siemGMr_6ZOwU
	log.SetLogger(logger)

	cfg := handler.VerifyJWTConfig{
		Header:       "Authorization",
		TokenType:    "Bearer",
		SignatureKey: "123456",
	}
	h := []goauth.AuthHandler{
		handler.NewVerifyJWT(cfg),
	}
	goauth.SetHandlers(h)

	r := mux.NewRouter()
	r.Use(goauth.Authenticate)
	r.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("pong"))
	})
	err := http.ListenAndServe(":8080", r)
	if err != nil {
		panic(err)
	}
}
