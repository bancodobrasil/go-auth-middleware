package main

import (
	"log"
	"net/http"

	goauth "github.com/bancodobrasil/go-auth-middleware"
	"github.com/bancodobrasil/go-auth-middleware/handler"
	"github.com/gorilla/mux"
)

func RunMuxExample() {
	r := mux.NewRouter()
	cfg := handler.VerifyAPIKeyConfig{
		Header: "X-API-Key",
		Key:    "123456",
	}
	h := []goauth.AuthHandler{
		handler.NewVerifyAPIKey(cfg),
	}
	goauth.SetHandlers(h)
	r.Use(goauth.Authenticate)
	r.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("pong"))
	})
	log.Fatal(http.ListenAndServe(":8080", r))
}
