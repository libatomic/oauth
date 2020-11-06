module github.com/libatomic/oauth

go 1.14

replace github.com/libatomic/api => ../api

// replace github.com/libatomic/litmus => ../litmus

require (
	github.com/apex/log v1.8.0
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/go-openapi/errors v0.19.6
	github.com/go-openapi/runtime v0.19.23
	github.com/go-openapi/strfmt v0.19.5
	github.com/go-openapi/swag v0.19.9
	github.com/go-openapi/validate v0.19.10
	github.com/go-ozzo/ozzo-validation/v4 v4.3.0
	github.com/golang/protobuf v1.4.3
	github.com/google/uuid v1.1.1
	github.com/gorilla/sessions v1.2.0
	github.com/jinzhu/copier v0.0.0-20201025035756-632e723a6687 // indirect
	github.com/lestrrat-go/jwx v1.0.3
	github.com/libatomic/api v1.0.17
	github.com/libatomic/litmus v0.5.3
	github.com/mitchellh/mapstructure v1.3.2
	github.com/mr-tron/base58 v1.2.0
	github.com/stretchr/testify v1.6.1
	github.com/ulule/deepcopier v0.0.0-20200430083143-45decc6639b6
	github.com/urfave/cli/v2 v2.3.0
	google.golang.org/grpc v1.33.0-dev
	google.golang.org/protobuf v1.25.0
)
