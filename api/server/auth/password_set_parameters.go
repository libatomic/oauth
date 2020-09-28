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
	"github.com/go-openapi/validate"
	"github.com/gorilla/mux"
)

// NewPasswordSetParams creates a new PasswordSetParams object
// no default values defined in spec.
func NewPasswordSetParams() PasswordSetParams {

	return PasswordSetParams{}
}

// PasswordSetParams contains all the bound params for the password set operation
// typically these are obtained from a http.Request
//
// swagger:parameters PasswordSet
type PasswordSetParams struct {
	/*The PKCE code verifier
	  Required: true
	  In: formData
	*/
	CodeVerifier string `json:"code_verifier"`

	/*The user's login
	  Required: true
	  In: formData
	*/
	Login string `json:"login"`

	/*The new password
	  Required: true
	  In: formData
	*/
	Password string `json:"password"`

	/*The uri to redirect to after password reset
	  In: formData
	*/
	RedirectURI *strfmt.URI `json:"redirect_uri"`

	/*The reset verification code
	  Required: true
	  In: formData
	*/
	ResetCode string `json:"reset_code"`

	// HTTP Request
	req *http.Request

	// HTTP Response
	res http.ResponseWriter
}

// Context returns the request context
func (o *PasswordSetParams) Context() context.Context {
	return o.req.Context()
}

// UnbindRequest returns the response and request associated with the parameters
func (o *PasswordSetParams) UnbindRequest() (http.ResponseWriter, *http.Request) {
	return o.res, o.req
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
func (o *PasswordSetParams) BindRequest(w http.ResponseWriter, r *http.Request, c ...runtime.Consumer) error {
	var res []error

	// ensure defaults
	*o = NewPasswordSetParams()

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

	if err := r.ParseMultipartForm(32 << 20); err != nil {
		if err != http.ErrNotMultipart {
			return errors.New(400, "%v", err)
		} else if err := r.ParseForm(); err != nil {
			return errors.New(400, "%v", err)
		}
	}
	fds := runtime.Values(r.Form)

	fdCodeVerifier, fdhkCodeVerifier, _ := fds.GetOK("code_verifier")
	if err := o.bindCodeVerifier(fdCodeVerifier, fdhkCodeVerifier, route.Formats); err != nil {
		res = append(res, err)
	}

	fdLogin, fdhkLogin, _ := fds.GetOK("login")
	if err := o.bindLogin(fdLogin, fdhkLogin, route.Formats); err != nil {
		res = append(res, err)
	}

	fdPassword, fdhkPassword, _ := fds.GetOK("password")
	if err := o.bindPassword(fdPassword, fdhkPassword, route.Formats); err != nil {
		res = append(res, err)
	}

	fdRedirectURI, fdhkRedirectURI, _ := fds.GetOK("redirect_uri")
	if err := o.bindRedirectURI(fdRedirectURI, fdhkRedirectURI, route.Formats); err != nil {
		res = append(res, err)
	}

	fdResetCode, fdhkResetCode, _ := fds.GetOK("reset_code")
	if err := o.bindResetCode(fdResetCode, fdhkResetCode, route.Formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindCodeVerifier binds and validates parameter CodeVerifier from formData.
func (o *PasswordSetParams) bindCodeVerifier(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("code_verifier", "formData", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true

	if err := validate.RequiredString("code_verifier", "formData", raw); err != nil {
		return err
	}

	o.CodeVerifier = raw

	return nil
}

// bindLogin binds and validates parameter Login from formData.
func (o *PasswordSetParams) bindLogin(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("login", "formData", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true

	if err := validate.RequiredString("login", "formData", raw); err != nil {
		return err
	}

	o.Login = raw

	return nil
}

// bindPassword binds and validates parameter Password from formData.
func (o *PasswordSetParams) bindPassword(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("password", "formData", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true

	if err := validate.RequiredString("password", "formData", raw); err != nil {
		return err
	}

	o.Password = raw

	return nil
}

// bindRedirectURI binds and validates parameter RedirectURI from formData.
func (o *PasswordSetParams) bindRedirectURI(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false

	if raw == "" { // empty values pass all other validations
		return nil
	}

	// Format: uri
	value, err := formats.Parse("uri", raw)
	if err != nil {
		return errors.InvalidType("redirect_uri", "formData", "strfmt.URI", raw)
	}
	o.RedirectURI = (value.(*strfmt.URI))

	if err := o.validateRedirectURI(formats); err != nil {
		return err
	}

	return nil
}

// validateRedirectURI carries on validations for parameter RedirectURI
func (o *PasswordSetParams) validateRedirectURI(formats strfmt.Registry) error {

	if err := validate.FormatOf("redirect_uri", "formData", "uri", o.RedirectURI.String(), formats); err != nil {
		return err
	}
	return nil
}

// bindResetCode binds and validates parameter ResetCode from formData.
func (o *PasswordSetParams) bindResetCode(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("reset_code", "formData", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true

	if err := validate.RequiredString("reset_code", "formData", raw); err != nil {
		return err
	}

	o.ResetCode = raw

	return nil
}
