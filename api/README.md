# The libatomic OAuth API

The libatomic OAuth API is comprised of these components

- `api/swagger.yaml` The OpenAPI 2.0 API definition document.
- `api/types` The generated API models shared by all components.
- `api/server` The REST API server that implements the spec operations.

This API is meant to be used in unison with a parent API and provides security and authorization
logic for that API.

## API Generation

Generating the API types is handled by the `Makefile` which executes `hack/generate-swagger-api.sh` via
the `quay.io/goswagger/swagger:latest` Docker container for [goswagger](https://goswagger.io/). The
generation script relies on `api/swagger-gen.yaml` to handle some minor customizationa of the code
building.

After making changes to `api/swagger.yaml` you need to run the following in the workspace root:

```bash
> make api-gen
```

## API Types

Many of the types this API uses are managed outside the scope of the library. This API provides no
mechanism for the creation of these objects. Implementers shall pass an `oauth.Controller` interface
object so the library can access the necessary objects from the parent API.

Implementers should extended the types to meet the needs of their backend.

## API Documenation

To view API docs you run `make api-docs`. This will start a service on [localhost](http://localhost:8002).
