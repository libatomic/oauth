// Code generated by go-swagger; DO NOT EDIT.

package auth

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/validate"
	"github.com/gorilla/mux"
)

// NewSignupParams creates a new SignupParams object
// no default values defined in spec.
func NewSignupParams() SignupParams {

	return SignupParams{}
}

// SignupParams contains all the bound params for the signup operation
// typically these are obtained from a http.Request
//
// swagger:parameters Signup
type SignupParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	/*The PKCE code verifier
	  Required: true
	  In: formData
	*/
	CodeVerifier string

	/*The user's email address
	  Required: true
	  In: formData
	*/
	Email strfmt.Email

	/*Inivitation codes allow for users to sign up when public sign up is disabled.

	  In: formData
	*/
	InviteCode *string

	/*The user's login
	  Required: true
	  In: formData
	*/
	Login string

	/*The user's full name
	  In: formData
	*/
	Name *string

	/*The user's password
	  Required: true
	  In: formData
	*/
	Password string

	/*"The authorization request token"

	  Required: true
	  In: formData
	*/
	RequestToken string
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
func (o *SignupParams) BindRequest(r *http.Request, c ...runtime.Consumer) error {
	var res []error

	// ensure defaults
	*o = NewSignupParams()

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

	fdEmail, fdhkEmail, _ := fds.GetOK("email")
	if err := o.bindEmail(fdEmail, fdhkEmail, route.Formats); err != nil {
		res = append(res, err)
	}

	fdInviteCode, fdhkInviteCode, _ := fds.GetOK("invite_code")
	if err := o.bindInviteCode(fdInviteCode, fdhkInviteCode, route.Formats); err != nil {
		res = append(res, err)
	}

	fdLogin, fdhkLogin, _ := fds.GetOK("login")
	if err := o.bindLogin(fdLogin, fdhkLogin, route.Formats); err != nil {
		res = append(res, err)
	}

	fdName, fdhkName, _ := fds.GetOK("name")
	if err := o.bindName(fdName, fdhkName, route.Formats); err != nil {
		res = append(res, err)
	}

	fdPassword, fdhkPassword, _ := fds.GetOK("password")
	if err := o.bindPassword(fdPassword, fdhkPassword, route.Formats); err != nil {
		res = append(res, err)
	}

	fdRequestToken, fdhkRequestToken, _ := fds.GetOK("request_token")
	if err := o.bindRequestToken(fdRequestToken, fdhkRequestToken, route.Formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindCodeVerifier binds and validates parameter CodeVerifier from formData.
func (o *SignupParams) bindCodeVerifier(rawData []string, hasKey bool, formats strfmt.Registry) error {
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

// bindEmail binds and validates parameter Email from formData.
func (o *SignupParams) bindEmail(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("email", "formData", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true

	if err := validate.RequiredString("email", "formData", raw); err != nil {
		return err
	}

	// Format: email
	value, err := formats.Parse("email", raw)
	if err != nil {
		return errors.InvalidType("email", "formData", "strfmt.Email", raw)
	}
	o.Email = *(value.(*strfmt.Email))

	if err := o.validateEmail(formats); err != nil {
		return err
	}

	return nil
}

// validateEmail carries on validations for parameter Email
func (o *SignupParams) validateEmail(formats strfmt.Registry) error {

	if err := validate.FormatOf("email", "formData", "email", o.Email.String(), formats); err != nil {
		return err
	}
	return nil
}

// bindInviteCode binds and validates parameter InviteCode from formData.
func (o *SignupParams) bindInviteCode(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false

	if raw == "" { // empty values pass all other validations
		return nil
	}

	o.InviteCode = &raw

	return nil
}

// bindLogin binds and validates parameter Login from formData.
func (o *SignupParams) bindLogin(rawData []string, hasKey bool, formats strfmt.Registry) error {
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

// bindName binds and validates parameter Name from formData.
func (o *SignupParams) bindName(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false

	if raw == "" { // empty values pass all other validations
		return nil
	}

	o.Name = &raw

	return nil
}

// bindPassword binds and validates parameter Password from formData.
func (o *SignupParams) bindPassword(rawData []string, hasKey bool, formats strfmt.Registry) error {
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

// bindRequestToken binds and validates parameter RequestToken from formData.
func (o *SignupParams) bindRequestToken(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("request_token", "formData", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true

	if err := validate.RequiredString("request_token", "formData", raw); err != nil {
		return err
	}

	o.RequestToken = raw

	return nil
}
