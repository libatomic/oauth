// Code generated by go-swagger; DO NOT EDIT.

package types

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// BearerToken BearerTokens are returned by the `/token` method. These token always include
// an `access_token` which can be used to access api methods from a related service.
//
// These are the only objects managed by the api itself. The integration is expected
// to implement the `AuthController` interface.
//
//
// swagger:model BearerToken
type BearerToken struct {

	// The token to be used for authorization
	// Required: true
	AccessToken string `json:"access_token"`

	// The time from `now` that the token expires
	// Required: true
	ExpiresIn int64 `json:"expires_in"`

	// The idenity token contains claims about the users identity. This token is
	// returned if the `openid` scope was granted.
	//
	// If the `profile` scope was granted, this will contain the user profile.
	//
	// These scopes are outside of the context of this library, it is up to the
	// provider to maintain these scopes.
	//
	IDToken string `json:"id_token,omitempty"`

	// The refresh token maybe used to generate a new access token so client
	// and user credentials do not have to traverse the wire again.
	//
	// The is provided if the `offline_access` scope is request.
	//
	// This scopes are outside of the context of this library, it is up to the
	// provider to maintain these scopes.
	//
	RefreshToken string `json:"refresh_token,omitempty"`

	// The token type, always Bearer
	// Required: true
	// Enum: [Bearer]
	TokenType string `json:"token_type"`

	// Additional properties added by the platform
	BearerToken map[string]map[string]interface{} `json:"-"`
}

// UnmarshalJSON unmarshals this object with additional properties from JSON
func (m *BearerToken) UnmarshalJSON(data []byte) error {
	// stage 1, bind the properties
	var stage1 struct {

		// The token to be used for authorization
		// Required: true
		AccessToken string `json:"access_token"`

		// The time from `now` that the token expires
		// Required: true
		ExpiresIn int64 `json:"expires_in"`

		// The idenity token contains claims about the users identity. This token is
		// returned if the `openid` scope was granted.
		//
		// If the `profile` scope was granted, this will contain the user profile.
		//
		// These scopes are outside of the context of this library, it is up to the
		// provider to maintain these scopes.
		//
		IDToken string `json:"id_token,omitempty"`

		// The refresh token maybe used to generate a new access token so client
		// and user credentials do not have to traverse the wire again.
		//
		// The is provided if the `offline_access` scope is request.
		//
		// This scopes are outside of the context of this library, it is up to the
		// provider to maintain these scopes.
		//
		RefreshToken string `json:"refresh_token,omitempty"`

		// The token type, always Bearer
		// Required: true
		// Enum: [Bearer]
		TokenType string `json:"token_type"`
	}
	if err := json.Unmarshal(data, &stage1); err != nil {
		return err
	}
	var rcv BearerToken

	rcv.AccessToken = stage1.AccessToken
	rcv.ExpiresIn = stage1.ExpiresIn
	rcv.IDToken = stage1.IDToken
	rcv.RefreshToken = stage1.RefreshToken
	rcv.TokenType = stage1.TokenType
	*m = rcv

	// stage 2, remove properties and add to map
	stage2 := make(map[string]json.RawMessage)
	if err := json.Unmarshal(data, &stage2); err != nil {
		return err
	}

	delete(stage2, "access_token")
	delete(stage2, "expires_in")
	delete(stage2, "id_token")
	delete(stage2, "refresh_token")
	delete(stage2, "token_type")
	// stage 3, add additional properties values
	if len(stage2) > 0 {
		result := make(map[string]map[string]interface{})
		for k, v := range stage2 {
			var toadd map[string]interface{}
			if err := json.Unmarshal(v, &toadd); err != nil {
				return err
			}
			result[k] = toadd
		}
		m.BearerToken = result
	}

	return nil
}

// MarshalJSON marshals this object with additional properties into a JSON object
func (m BearerToken) MarshalJSON() ([]byte, error) {
	var stage1 struct {

		// The token to be used for authorization
		// Required: true
		AccessToken string `json:"access_token"`

		// The time from `now` that the token expires
		// Required: true
		ExpiresIn int64 `json:"expires_in"`

		// The idenity token contains claims about the users identity. This token is
		// returned if the `openid` scope was granted.
		//
		// If the `profile` scope was granted, this will contain the user profile.
		//
		// These scopes are outside of the context of this library, it is up to the
		// provider to maintain these scopes.
		//
		IDToken string `json:"id_token,omitempty"`

		// The refresh token maybe used to generate a new access token so client
		// and user credentials do not have to traverse the wire again.
		//
		// The is provided if the `offline_access` scope is request.
		//
		// This scopes are outside of the context of this library, it is up to the
		// provider to maintain these scopes.
		//
		RefreshToken string `json:"refresh_token,omitempty"`

		// The token type, always Bearer
		// Required: true
		// Enum: [Bearer]
		TokenType string `json:"token_type"`
	}

	stage1.AccessToken = m.AccessToken
	stage1.ExpiresIn = m.ExpiresIn
	stage1.IDToken = m.IDToken
	stage1.RefreshToken = m.RefreshToken
	stage1.TokenType = m.TokenType

	// make JSON object for known properties
	props, err := json.Marshal(stage1)
	if err != nil {
		return nil, err
	}

	if len(m.BearerToken) == 0 {
		return props, nil
	}

	// make JSON object for the additional properties
	additional, err := json.Marshal(m.BearerToken)
	if err != nil {
		return nil, err
	}

	if len(props) < 3 {
		return additional, nil
	}

	// concatenate the 2 objects
	props[len(props)-1] = ','
	return append(props, additional[1:]...), nil
}

// Validate validates this bearer token
func (m *BearerToken) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAccessToken(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateExpiresIn(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTokenType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *BearerToken) validateAccessToken(formats strfmt.Registry) error {

	if err := validate.RequiredString("access_token", "body", string(m.AccessToken)); err != nil {
		return err
	}

	return nil
}

func (m *BearerToken) validateExpiresIn(formats strfmt.Registry) error {

	if err := validate.Required("expires_in", "body", int64(m.ExpiresIn)); err != nil {
		return err
	}

	return nil
}

var bearerTokenTypeTokenTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["Bearer"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		bearerTokenTypeTokenTypePropEnum = append(bearerTokenTypeTokenTypePropEnum, v)
	}
}

const (

	// BearerTokenTokenTypeBearer captures enum value "Bearer"
	BearerTokenTokenTypeBearer string = "Bearer"
)

// prop value enum
func (m *BearerToken) validateTokenTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, bearerTokenTypeTokenTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *BearerToken) validateTokenType(formats strfmt.Registry) error {

	if err := validate.RequiredString("token_type", "body", string(m.TokenType)); err != nil {
		return err
	}

	// value enum
	if err := m.validateTokenTypeEnum("token_type", "body", m.TokenType); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *BearerToken) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *BearerToken) UnmarshalBinary(b []byte) error {
	var res BearerToken
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
