package main

import (
	"os"

	"github.com/bancodobrasil/goauth/examples/apikey"
	"github.com/bancodobrasil/goauth/examples/jwt"
	"github.com/bancodobrasil/goauth/log"
)

func main() {
	logger := log.NewDefaultLogger(log.Debug)
	log.SetLogger(logger)

	if len(os.Args) < 2 {
		logger.Log(log.Panic, "You must provide an argument with the example to run")
	}

	switch os.Args[1] {
	case "apikey", "api_key", "api-key":
		if len(os.Args) < 3 {
			logger.Log(log.Panic, "You must provide an argument with the name of the framework to use")
		}
		switch os.Args[2] {
		case "gin":
			apikey.Gin()
			break
		case "mux":
			apikey.Mux()
			break
		default:
			log.Log(log.Panic, "Invalid framework name")
		}
		break
	case "jwt":
		if len(os.Args) < 3 {
			log.Log(log.Panic, "You must provide an argument with the name of the framework to use")
		}
		switch os.Args[2] {
		case "mux":
			jwt.Mux()
			break
		}
	default:
		logger.Log(log.Panic, "Invalid example name")
	}
}
