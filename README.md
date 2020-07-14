# Atomic Auth Provider

The `auth.AuthProvider` interface provides simple user, application, and audience management for api servers.

This library does not implment this interface, which is outside the scope of its definition. Other services
like (libatomic/atomic)[https://github.com/libatomic/atomic] provide examples this interface in the backend
definition.

## Auth Server

This server implements a simple http auth server that attempts to remain simple and yet implement
many of the common flows using the `auth.AuthProvider` interface. You can use this template to create a
more custom provider as needed.

This library is meant to be consumed by other services and does not provide an independent
functionality.

## Integrating the server

Integration begins with instantiating a `api/server.Server` object.

This object implements the http.Hander interface, provides a `gorilla/mux.Router` as well as a standalone
http.Server. These options provide considerable flexibility. If you need more, simply fork, hack, repeat.

Integrators will need to implement the `pkg/oauth.Controller` interface.

The `api/server.Server` implements the `pkg/oauth.Authorizer` interface which can be used to validate
incoming bearer tokens on http.Request objects.

## OAuth 2.0 flow support

This library supports `client_credentials`, `authorization_code`, and `refresh_token` grants. The parameters
are documented in the `api/swagger.yaml` spefification.

## Cookie storage

The `api/server.Server` object can be passed a mux/sessions.Store option for alternate session cookie
storage for browser based flows. The default store is `mux/sessions.CookieStore`.

## AuthCode storage

AuthCodes require semi-persistence between the `/authorize` call and the `/token` call. The default store
is the in-memory cache store provided by `pkg/memstore`.
