package jwks

import (
	"context"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// Copied from: https://github.com/lestrrat-go/jwx/issues/812#issuecomment-1231137870

// KeyFetcher allows other parts of your code to implement a simple key lookup.
// Pair with jwk.FromRaw or similar for returning results.
type KeyFetcher func(c context.Context, keyID string) (jwk.Key, error)

// KeyHandler wraps a KeyFetcher to implement jws.KeyProvider.
// This is used in tandem with jwt.Parse to provide dynamic key lookup.
//
// In a more complex system, you might add logging, metrics, caching, rate limiting...
type KeyHandler struct {
	Fetcher KeyFetcher
}

func (h *KeyHandler) FetchKeys(c context.Context, result jws.KeySink, sig *jws.Signature, msg *jws.Message) error {

	// Extract whatever you need from jws.Headers
	alg := sig.ProtectedHeaders().Algorithm()
	kid := sig.ProtectedHeaders().KeyID()

	// Run the dynamic key lookup
	key, err := h.Fetcher(c, kid)
	if err != nil {
		return err
	}

	// Check that the fetched key is marked with the correct key ID
	fetched_kid := key.KeyID()
	if kid != fetched_kid {
		return fmt.Errorf("Fetching kid '%s' returned different kid '%s'", kid, fetched_kid)
	}

	// Mark as parse candidate
	result.Key(alg, key)
	return nil
}

// Trivial usage
// func Parse(c context.Context, jwtRaw []byte, handler *KeyHandler) (jwt.Token, error) {

// 	// From jwt.WithContext docs: soon a context will be part of the function signature
// 	// May as well take a context now to be ready for the API change
// 	return jwt.Parse(jwtRaw, jwt.WithKeyProvider(handler), jwt.WithContext(c))
// }
