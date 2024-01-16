package apikey

import (
	"net/http"

	"github.com/bancodobrasil/goauth"
	"github.com/bancodobrasil/goauth/handler"
	"github.com/bancodobrasil/goauth/log"
	"github.com/gorilla/mux"
)

// Mux runs the example using Gorilla Mux
func Mux(logger log.Logger) {
	log.SetLogger(logger)

	cfg := handler.VerifyAPIKeyConfig{
		Header: "X-API-Key",
		Keys:   []string{"123", "456"},
	}
	h := []goauth.AuthHandler{
		handler.NewVerifyAPIKey(cfg),
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
