// Code generated by go-swagger; DO NOT EDIT.

package oauth

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// Application Applications are API clients that access APIs managed by the integration
// service. Applications may provide user authentication flows.
// Applications are managed by the `oauth.Controller`.
//
//
// swagger:model Application
type Application struct {

	// The applications allowed grant types
	// Required: true
	AllowedGrants []string `json:"allowed_grants"`

	// This is an array of the application's allowed application uris. These are checked
	// in the `/authorize` path to ensure the redirect is allowed by the application.
	// This path on redirect will receive the following query parameters:
	//   - `auth_request`: An encoded and signed request value to be forwarded to various posts.
	//
	AppUris []string `json:"app_uris"`

	// The application client id used for oauth grants
	// Read Only: true
	ClientID string `json:"client_id,omitempty"`

	// The application client secret used for oauth grants
	// Read Only: true
	ClientSecret string `json:"client_secret,omitempty"`

	// The application description
	Description string `json:"description,omitempty"`

	// The application name
	// Required: true
	Name string `json:"name"`

	// The application's authorized permissions
	Permissions []string `json:"permissions"`

	// This is an array of the application's allowed redirect uris. These are checked
	// in the `/login` path to ensure the redirect is allowed by the application.
	// This path on redirect will receive the following query parameters:
	//   - `code`: A signed authorization code that can be passed to the `/token` path.
	//
	RedirectUris []string `json:"redirect_uris"`

	// The lifetime for identity tokens in seconds, provided the call requested the
	// `openid` scopes.
	//
	TokenLifetime int64 `json:"token_lifetime,omitempty"`

	// The application type
	// Enum: [web native machine]
	Type string `json:"type,omitempty"`
}

// Validate validates this application
func (m *Application) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAllowedGrants(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var applicationAllowedGrantsItemsEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["authorization_code","client_credentials","refresh_token"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		applicationAllowedGrantsItemsEnum = append(applicationAllowedGrantsItemsEnum, v)
	}
}

func (m *Application) validateAllowedGrantsItemsEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, applicationAllowedGrantsItemsEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *Application) validateAllowedGrants(formats strfmt.Registry) error {

	if err := validate.Required("allowed_grants", "body", m.AllowedGrants); err != nil {
		return err
	}

	for i := 0; i < len(m.AllowedGrants); i++ {

		// value enum
		if err := m.validateAllowedGrantsItemsEnum("allowed_grants"+"."+strconv.Itoa(i), "body", m.AllowedGrants[i]); err != nil {
			return err
		}

	}

	return nil
}

func (m *Application) validateName(formats strfmt.Registry) error {

	if err := validate.RequiredString("name", "body", string(m.Name)); err != nil {
		return err
	}

	return nil
}

var applicationTypeTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["web","native","machine"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		applicationTypeTypePropEnum = append(applicationTypeTypePropEnum, v)
	}
}

const (

	// ApplicationTypeWeb captures enum value "web"
	ApplicationTypeWeb string = "web"

	// ApplicationTypeNative captures enum value "native"
	ApplicationTypeNative string = "native"

	// ApplicationTypeMachine captures enum value "machine"
	ApplicationTypeMachine string = "machine"
)

// prop value enum
func (m *Application) validateTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, applicationTypeTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *Application) validateType(formats strfmt.Registry) error {

	if swag.IsZero(m.Type) { // not required
		return nil
	}

	// value enum
	if err := m.validateTypeEnum("type", "body", m.Type); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *Application) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Application) UnmarshalBinary(b []byte) error {
	var res Application
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
