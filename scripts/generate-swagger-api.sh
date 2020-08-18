#!/bin/sh
set -eu

swagger generate model -f api/swagger.yaml \
	-t pkg -m oauth -C api/swagger-gen.yaml \
	--template=atomic

swagger generate operation -f api/swagger.yaml \
	-t api -a server -m oauth -C api/swagger-gen.yaml \
	--template=atomic --skip-responses --skip-url-builder 

# generate the embedded spec file
swagger generate server -f api/swagger.yaml \
	-t api -s server --template=atomic -C api/swagger-gen.yaml \
	--skip-models --skip-operations --exclude-main
