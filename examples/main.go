package main

import (
	"os"

	"github.com/bancodobrasil/goauth/examples/api_key"
	"github.com/bancodobrasil/goauth/examples/jwt"
)

func main() {
	logger := &Logger{}

	if len(os.Args) < 2 {
		logger.Log(5, "You must provide an argument with the example to run")
	}

	switch os.Args[1] {
	case "api_key":
		if len(os.Args) < 3 {
			logger.Log(5, "You must provide an argument with the name of the framework to use")
		}
		switch os.Args[2] {
		case "gin":
			api_key.ApiKeyGin(logger)
			break
		case "mux":
			api_key.ApiKeyMux(logger)
			break
		default:
			logger.Log(5, "Invalid framework name")
		}
		break
	case "jwt":
		if len(os.Args) < 3 {
			logger.Log(5, "You must provide an argument with the name of the framework to use")
		}
		switch os.Args[2] {
		case "mux":
			jwt.JwtMux(logger)
			break
		}
	default:
		logger.Log(5, "Invalid example name")
	}
}
