# Go Auth Middleware

This library is a generic authentication middleware that implements `http.Handler`
and can be used with any framework of choice like `gin` and `mux` (see [examples](./examples/)).

It accepts multiple authentication "handlers" that are executed in order, and the rules are:

- The request proceeds if any of the handlers does NOT return an error
- The request is aborted if the last handler return an error

## Handlers

The library provides the following authentication handlers:

### API Key

The `API Key` handler can be used for authentication using a single API Key.

You must specify the `Header` and `Key` in the configuration.

### JWKS

The `JWKS` handler is used for authentication with [JWK](https://www.rfc-editor.org/rfc/rfc7517)
contained in the `Authorization` Header of the request with the `Bearer` format, example:
```
Authorization: Bearer 123abc_any_JWK_here
```

You must specify the `URL` and `CacheConfig` in the configuration.

## Logging

You can implement the `Logger` interface of the package `log` of this library,
so that you can handle logs in your app.

Set the logger by passing your implementation to `log.SetLogger(l Logger)`.
