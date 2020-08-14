// Code generated by go-swagger; DO NOT EDIT.

package auth

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
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

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	HTTPResponse http.ResponseWriter `json:"-"`
}

func (o *PublicKeyGetParams) RW() (*http.Request, http.ResponseWriter) {
	return o.HTTPRequest, o.HTTPResponse
}

func (o *PublicKeyGetParams) WR() (http.ResponseWriter, *http.Request) {
	return o.HTTPResponse, o.HTTPRequest
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
func (o *PublicKeyGetParams) BindRequest(w http.ResponseWriter, r *http.Request, c ...runtime.Consumer) error {
	return o.BindRequestW(nil, r, c...)
}

// BindRequestW both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
func (o *PublicKeyGetParams) BindRequestW(w http.ResponseWriter, r *http.Request, c ...runtime.Consumer) error {
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

	o.HTTPRequest = r
	o.HTTPResponse = w

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}