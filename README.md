# Atomic OAuth 2.0 Provider

This provider implements a Simple OAuth 2.0 provider that attempts to remain simple and yet implement
many of the common flows. You can use this template to create a more custom provider as needed.

This library is meant to be consumed by other services and does not provide an independent
functionality.

## Integrating the server

Integration begins with instantiating a `api\server.Server` object.

This object implements the http.Hander interface, provides a `gorilla/mux.Router` as well as a standalone
http.Server. These options provide considerable flexibility. If you need more, simply fork, hack, repeat.
