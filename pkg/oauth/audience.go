// Code generated by go-swagger; DO NOT EDIT.

package oauth

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"database/sql/driver"
	"encoding/json"
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// Audience An audience is an API that applications can request permission to access on behalf of
// a user or itself.
//
//
// swagger:model Audience
type Audience struct {

	// The audience description
	Description string `json:"description,omitempty"`

	// The name of the audience. This is used in token request and token claims.
	// This must match `/?[a-zA-Z0-9][a-zA-Z0-9_.-:]+`.
	//
	// Required: true
	Name string `json:"name"`

	// permissions
	Permissions Permissions `json:"permissions,omitempty"`

	// The audience token signing algorithm
	// Enum: [RS256 HS256]
	TokenAlgorithm string `json:"token_algorithm,omitempty"`

	// The lifetime for tokens created on behalf of this audience, in seconds
	TokenLifetime int64 `json:"token_lifetime,omitempty"`

	// The signing secret used if the algorithm is HS256
	TokenSecret string `json:"token_secret,omitempty"`
}

// Validate validates this audience
func (m *Audience) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePermissions(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTokenAlgorithm(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Audience) validateName(formats strfmt.Registry) error {

	if err := validate.RequiredString("name", "body", string(m.Name)); err != nil {
		return err
	}

	return nil
}

func (m *Audience) validatePermissions(formats strfmt.Registry) error {

	if swag.IsZero(m.Permissions) { // not required
		return nil
	}

	if err := m.Permissions.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("permissions")
		}
		return err
	}

	return nil
}

var audienceTypeTokenAlgorithmPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["RS256","HS256"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		audienceTypeTokenAlgorithmPropEnum = append(audienceTypeTokenAlgorithmPropEnum, v)
	}
}

const (

	// AudienceTokenAlgorithmRS256 captures enum value "RS256"
	AudienceTokenAlgorithmRS256 string = "RS256"

	// AudienceTokenAlgorithmHS256 captures enum value "HS256"
	AudienceTokenAlgorithmHS256 string = "HS256"
)

// prop value enum
func (m *Audience) validateTokenAlgorithmEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, audienceTypeTokenAlgorithmPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *Audience) validateTokenAlgorithm(formats strfmt.Registry) error {

	if swag.IsZero(m.TokenAlgorithm) { // not required
		return nil
	}

	// value enum
	if err := m.validateTokenAlgorithmEnum("token_algorithm", "body", m.TokenAlgorithm); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *Audience) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Audience) UnmarshalBinary(b []byte) error {
	var res Audience
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// Value returns Audience as a value that can be stored as json in the database
func (m Audience) Value() (driver.Value, error) {
	return json.Marshal(m)
}

// Scan reads a json value from the database into a Audience
func (m *Audience) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New(http.StatusInternalServerError, "type assertion to []byte failed")
	}

	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}

	return nil
}
