module github.com/libatomic/oauth

go 1.14

// replace github.com/libatomic/api => ../api

replace github.com/libatomic/litmus => ../litmus

require (
	github.com/apex/log v1.8.0
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/go-openapi/errors v0.19.6
	github.com/go-openapi/loads v0.19.5
	github.com/go-openapi/runtime v0.19.20
	github.com/go-openapi/strfmt v0.19.5
	github.com/go-openapi/swag v0.19.9
	github.com/go-openapi/validate v0.19.10
	github.com/google/uuid v1.1.1
	github.com/gorilla/mux v1.7.4
	github.com/gorilla/sessions v1.2.0
	github.com/lestrrat-go/jwx v1.0.3
	github.com/libatomic/api v1.0.5
	github.com/libatomic/litmus v0.5.3
	github.com/mitchellh/mapstructure v1.3.2
	github.com/mr-tron/base58 v1.2.0
	github.com/stretchr/testify v1.6.1
)
