# Go Auth Middleware

This library is a generic authentication middleware that implements `http.Handler`
and can be used with any framework of choice like `gin` and `mux` (see [examples](./examples/)).

It accepts multiple authentication "handlers" that are executed in order, and the rules are:

- The request proceeds if any of the handlers does NOT return an error
- The request is aborted if the last handler return an error

## Handlers

The library provides the following authentication handlers:

### API Key

The `api_key` handler can be used for verifying if a specific Header of the request contains one of the allowed Keys.

#### API Key handler configuration:

| Config Name | Environment Variable | Required | Value Type | Default Value |
|-------------|----------------------|----------|------------|---------------|
|Keys|`GOAUTH_API_KEY_LIST`|true|`[]string` (comma-separated values)|-|
|Header|`GOAUTH_API_KEY_HEADER`|false|`string`|X-API-Key`|

### JWKS

The `jwks` handler is used for verifying a signed `JWT` (i.e., a `JWS`) using a signature key from a remote [JWK](https://www.rfc-editor.org/rfc/rfc7517) Set.

It looks up for the signed token in a specific Header of the request (with an optional prefix), e.g.:

```http
Authorization: Bearer 123abc_any_signed_JWT_here
```

#### JWKS handler configuration:

| Config Name | Environment Variable | Required | Value Type | Default Value |
|-------------|----------------------|----------|-------------|--------------|
|URL|`GOAUTH_JWKS_URL`|true|`string`|-|
|Header|`GOAUTH_JWKS_HEADER`|false|`string`|`Authorization`|
|Token Type|`GOAUTH_JWKS_TOKEN_TYPE`|false|`string`|`Bearer`|
|Refresh Window|`GOAUTH_JWKS_REFRESH_WINDOW`|false|`int`|60|
|Min Refresh Interval|`GOAUTH_JWKS_MIN_REFRESH_INTERVAL`|false|`int`|300|
|Payload Context Key|`GOAUTH_JWKS_PAYLOAD_CONTEXT_KEY`|false|`string`|`USER`|

### Signed JWT (JWS)

The `jwt` handler is used for verifying a signed `JWT` (i.e., a `JWS`) using the specified `Signature Key` and `Algorithim`.

It looks up for the signed token in a specific Header of the request (with an optional prefix), e.g.:

```http
Authorization: Bearer 123abc_any_signed_JWT_here
```

#### JWT handler configuration:

| Config Name | Environment Variable | Required | Value Type | Default Value |
|-------------|----------------------|----------|-------------|--------------|
|Signature Key|`GOAUTH_JWT_SIGNATURE_KEY`|true|`string`|-|
|Signature Algorithm|`GOAUTH_JWT_SIGNATURE_ALGORITHM`|false|`string`|`RS256`|
|Header|`GOAUTH_JWT_HEADER`|false|`string`|`Authorization`|
|Token Type|`GOAUTH_JWT_TOKEN_TYPE`|false|`string`|`Bearer`|
|Payload Context Key|`GOAUTH_JWT_PAYLOAD_CONTEXT_KEY`|false|`string`|`USER`|

## Logging

You can implement the `Logger` interface of the package `log` of this library,
so that you can handle logs in your app.

Set the logger by passing your implementation to `log.SetLogger(l Logger)`.
