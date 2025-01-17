package goauth

import (
	"fmt"
	"net/http"
)

var h []AuthHandler = []AuthHandler{}

// AuthHandler is the interface that wraps the AuthenticateFunc method
// and is used to authenticate the request
type AuthHandler interface {
	Handle(h *http.Request) (request *http.Request, statusCode int, err error)
}

// AuthMiddlewareError is the error type returned by the middleware
type AuthMiddlewareError struct {
	// Code is the HTTP status code
	Code int
	// Message is the error message
	Message string
}

// Error implements the error interface
func (e *AuthMiddlewareError) Error() string {
	return e.Message
}

// GetHandlers returns the authentication handlers
func GetHandlers() []AuthHandler {
	return h
}

// SetHandlers sets the authentication handlers
func SetHandlers(handlers []AuthHandler) {
	h = handlers
}

// Authenticate executes all the authentication handlers in the order they were added.
// If any of the handlers does not return an error, the request proceeds to the next handler.
// If the last handler returns an error, the request is aborted.
func Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		var statusCode int
		request := r

		for _, handler := range h {
			request, statusCode, err = handler.Handle(r)
			if err == nil {
				break
			}
		}

		if err != nil {
			respondWithError(w, &AuthMiddlewareError{
				Code:    statusCode,
				Message: err.Error(),
			})
			return
		}

		if next != nil {
			next.ServeHTTP(w, request)
		}
	})
}

// Helper function to abort the request with an error status code and message
func respondWithError(w http.ResponseWriter, err *AuthMiddlewareError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.Code)
	str := `{"error":"%s"}`
	http.Error(w, fmt.Sprintf(str, err.Message), err.Code)
}
