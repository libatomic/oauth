#!/bin/sh
set -eu

swagger generate model -f api/swagger.yaml \
	-t pkg -m oauth -C api/swagger-gen.yaml \
	-n ErrorResponse \
	-n BearerToken \
	-n AuthRequest \
	-n AuthCode \
	-n Session \
	-n Application \
	-n Audience \
	-n Address \
	-n Profile \
	-n User

swagger generate operation -f api/swagger.yaml \
	-t api -a rest -C api/swagger-gen.yaml \
	-T api/templates --skip-responses --skip-url-builder \
	-n Authorize \
	-n Login \
	-n Token \
	-n Logout \
	-n UserInfoGet \
	-n UserInfoUpdate \
	-n Signup \
	-n PasswordReset

# generate the embedded spec file
swagger generate server -f api/swagger.yaml \
	-t api -s rest -T api/templates -C api/swagger-gen.yaml \
	--skip-models --skip-operations --exclude-main
