package jwt

import (
	"net/http"

	"github.com/bancodobrasil/goauth"
	"github.com/bancodobrasil/goauth/handler"
	"github.com/bancodobrasil/goauth/log"
	"github.com/gorilla/mux"
)

// Mux runs the example using Gorilla Mux
func Mux() {
	cfg := handler.VerifyJWTConfig{
		Header:             "Authorization",
		TokenType:          "Bearer",
		SignatureKey:       "123456",
		SignatureAlgorithm: "HS256",
		PayloadContextKey:  "USER",
	}
	h := []goauth.AuthHandler{
		handler.NewVerifyJWT(cfg),
	}
	goauth.SetHandlers(h)

	r := mux.NewRouter()
	r.Use(goauth.Authenticate)
	r.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("USER")
		log.Log(log.Info, user)
		w.Write([]byte("pong"))
	})
	err := http.ListenAndServe(":8081", r)
	if err != nil {
		panic(err)
	}
}
