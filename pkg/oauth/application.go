// Code generated by go-swagger; DO NOT EDIT.

package oauth

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"database/sql/driver"
	"encoding/json"
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// Application Applications are API clients that access APIs managed by the integration
// service. Applications may provide user authentication flows.
// Applications are managed by the `oauth.Controller`. This library provides
// an incomplete base definition for application clients.
//
// ## API URLs
// This is an array of the application's allowed application uris. These are checked
// in the `/authorize` path to ensure the redirect is allowed by the application.
// This path on redirect will receive the following query parameters:
//
//   - `auth_request`: An encoded and signed request value to be forwarded to various posts.
//
// ## Redirect URIs
// This is an array of the application's allowed redirect uris. These are checked
// in the `/login` path to ensure the redirect is allowed by the application.
// This path on redirect will receive the following query parameters:
//
// - `code`: A signed authorization code that can be passed to the `/token` path.
//
// ## User Pools
// User pools are groups of users that the application can access. The implementaiton
// of such is outside the scope of this API.
//
//
// swagger:model Application
type Application struct {

	// allowed grants
	AllowedGrants Permissions `json:"allowed_grants,omitempty"`

	// app uris
	AppUris Permissions `json:"app_uris,omitempty"`

	// The application client id used for oauth grants
	// Read Only: true
	ClientID string `json:"client_id,omitempty"`

	// The application client secret used for oauth grants
	// Read Only: true
	ClientSecret string `json:"client_secret,omitempty"`

	// The application description
	Description *string `json:"description,omitempty"`

	// The application name
	Name string `json:"name,omitempty"`

	// permissions
	Permissions PermissionSet `json:"permissions,omitempty"`

	// redirect uris
	RedirectUris Permissions `json:"redirect_uris,omitempty"`

	// The lifetime for identity tokens in seconds, provided the call requested the
	// `openid` scopes.
	//
	TokenLifetime int64 `json:"token_lifetime,omitempty"`

	// The application type
	// Enum: [web native machine]
	Type string `json:"type,omitempty"`

	// user pools
	UserPools Permissions `json:"user_pools,omitempty"`
}

// Validate validates this application
func (m *Application) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAllowedGrants(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAppUris(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePermissions(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRedirectUris(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUserPools(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Application) validateAllowedGrants(formats strfmt.Registry) error {

	if swag.IsZero(m.AllowedGrants) { // not required
		return nil
	}

	if err := m.AllowedGrants.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("allowed_grants")
		}
		return err
	}

	return nil
}

func (m *Application) validateAppUris(formats strfmt.Registry) error {

	if swag.IsZero(m.AppUris) { // not required
		return nil
	}

	if err := m.AppUris.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("app_uris")
		}
		return err
	}

	return nil
}

func (m *Application) validatePermissions(formats strfmt.Registry) error {

	if swag.IsZero(m.Permissions) { // not required
		return nil
	}

	if v, ok := interface{}(m.Permissions).(runtime.Validatable); ok {
		if err := v.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("permissions")
			}
			return err
		}
	}

	return nil
}

func (m *Application) validateRedirectUris(formats strfmt.Registry) error {

	if swag.IsZero(m.RedirectUris) { // not required
		return nil
	}

	if err := m.RedirectUris.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("redirect_uris")
		}
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

func (m *Application) validateUserPools(formats strfmt.Registry) error {

	if swag.IsZero(m.UserPools) { // not required
		return nil
	}

	if err := m.UserPools.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("user_pools")
		}
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

// Value returns Application as a value that can be stored as json in the database
func (m Application) Value() (driver.Value, error) {
	return json.Marshal(m)
}

// Scan reads a json value from the database into a Application
func (m *Application) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New(http.StatusInternalServerError, "type assertion to []byte failed")
	}

	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}

	return nil
}
