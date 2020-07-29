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

// User A user is a user object
//
//
// swagger:model User
type User struct {

	// The user's login
	//
	// Required: true
	Login string `json:"login"`

	// The time the user password expirts
	// Format: date-time
	PasswordExpiresAt strfmt.DateTime `json:"password_expires_at,omitempty"`

	// permissions
	Permissions PermissionSet `json:"permissions,omitempty"`

	// profile
	Profile Profile `json:"profile,omitempty"`
}

// Validate validates this user
func (m *User) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateLogin(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePasswordExpiresAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePermissions(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProfile(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *User) validateLogin(formats strfmt.Registry) error {

	if err := validate.RequiredString("login", "body", string(m.Login)); err != nil {
		return err
	}

	return nil
}

func (m *User) validatePasswordExpiresAt(formats strfmt.Registry) error {

	if swag.IsZero(m.PasswordExpiresAt) { // not required
		return nil
	}

	if err := validate.FormatOf("password_expires_at", "body", "date-time", m.PasswordExpiresAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *User) validatePermissions(formats strfmt.Registry) error {

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

func (m *User) validateProfile(formats strfmt.Registry) error {

	if swag.IsZero(m.Profile) { // not required
		return nil
	}

	if err := m.Profile.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("profile")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *User) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *User) UnmarshalBinary(b []byte) error {
	var res User
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// Value returns User as a value that can be stored as json in the database
func (m User) Value() (driver.Value, error) {
	return json.Marshal(m)
}

// Scan reads a json value from the database into a User
func (m *User) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New(http.StatusInternalServerError, "type assertion to []byte failed")
	}

	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}

	return nil
}
