// Code generated by go-swagger; DO NOT EDIT.

package auth

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

// NewPublicKeyGetParams creates a new PublicKeyGetParams object
// no default values defined in spec.
func NewPublicKeyGetParams() PublicKeyGetParams {

	return PublicKeyGetParams{}
}

// PublicKeyGetParams contains all the bound params for the public key get operation
// typically these are obtained from a http.Request
//
// swagger:parameters PublicKeyGet
type PublicKeyGetParams struct {
	/*The audience for the request
	  In: query
	*/
	Audience *string

	// HTTP Request
	req *http.Request

	// HTTP Response
	res http.ResponseWriter
}

// Context returns the request context
func (o *PublicKeyGetParams) Context() context.Context {
	return o.req.Context()
}

// UnbindRequest returns the response and request associated with the parameters
func (o *PublicKeyGetParams) UnbindRequest() (http.ResponseWriter, *http.Request) {
	return o.res, o.req
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
func (o *PublicKeyGetParams) BindRequest(w http.ResponseWriter, r *http.Request, c ...runtime.Consumer) error {
	var res []error

	// ensure defaults
	*o = NewPublicKeyGetParams()

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

	qs := runtime.Values(r.URL.Query())

	qAudience, qhkAudience, _ := qs.GetOK("audience")
	if err := o.bindAudience(qAudience, qhkAudience, route.Formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindAudience binds and validates parameter Audience from query.
func (o *PublicKeyGetParams) bindAudience(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false
	// AllowEmptyValue: false
	if raw == "" { // empty values pass all other validations
		return nil
	}

	o.Audience = &raw

	return nil
}
