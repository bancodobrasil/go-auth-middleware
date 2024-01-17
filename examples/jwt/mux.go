package jwt

import (
	"net/http"

	"github.com/bancodobrasil/goauth"
	"github.com/bancodobrasil/goauth/handler"
	"github.com/gorilla/mux"
)

// Mux runs the example using Gorilla Mux
func Mux() {
	cfg := handler.VerifyJWTConfig{
		Header:             "Authorization",
		TokenType:          "Bearer",
		SignatureKey:       "123456",
		SignatureAlgorithm: "HS256",
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
