// Code generated by go-swagger; DO NOT EDIT.

package user

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/gorilla/mux"
)

// NewUserInfoGetParams creates a new UserInfoGetParams object
// no default values defined in spec.
func NewUserInfoGetParams() UserInfoGetParams {

	return UserInfoGetParams{}
}

// UserInfoGetParams contains all the bound params for the user info get operation
// typically these are obtained from a http.Request
//
// swagger:parameters UserInfoGet
type UserInfoGetParams struct {

	// HTTP Request
	req *http.Request

	// HTTP Response
	res http.ResponseWriter
}

// Context returns the request context
func (o *UserInfoGetParams) Context() context.Context {
	return o.req.Context()
}

// UnbindRequest returns the response and request associated with the parameters
func (o *UserInfoGetParams) UnbindRequest() (http.ResponseWriter, *http.Request) {
	return o.res, o.req
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
func (o *UserInfoGetParams) BindRequest(w http.ResponseWriter, r *http.Request, c ...runtime.Consumer) error {
	var res []error

	// ensure defaults
	*o = NewUserInfoGetParams()

	vars := mux.Vars(r)
	route := struct {
		Consumer runtime.Consumer
		Formats  strfmt.Registry
		GetOK    func(name string) ([]string, bool, bool)
	}{
		Consumer: runtime.JSONConsumer(),
		Formats:  strfmt.NewFormats(),
		GetOK: func(name string) ([]string, bool, bool) {
			val, ok := vars[name]
			if !ok {
				return nil, false, false
			}
			return []string{val}, true, val != ""
		},
	}

	if len(c) > 0 {
		route.Consumer = c[0]
	}

	o.req = r
	o.res = w

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
