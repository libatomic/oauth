package oauth

import (
	"database/sql/driver"
	"encoding/json"
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// AuthRequest An AuthRequest is generated by the `/authorize` call and passed to the `app_uri`.
// The properties of AuthRequest map to the parameters of the `/authorize` operation.
// This request is encoded and signed by the authorization service and must be passed
// in the POST to `/login` to validate the authentication request.
//
//
type AuthRequest struct {

	// The request audience
	// Required: true
	Audience string `json:"audience"`

	// The request client id
	// Required: true
	ClientID string `json:"client_id"`

	// The request code challenge
	// Required: true
	CodeChallenge string `json:"code_challenge"`

	// The request code challenge method
	// Enum: [S256]
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`

	// The request expiration epoch
	ExpiresAt int64 `json:"expires_at,omitempty"`

	// The request redirect uri
	// Required: true
	RedirectURI string `json:"redirect_uri"`

	// scope
	Scope Permissions `json:"scope,omitempty"`

	// The request state
	State *string `json:"state,omitempty"`

	// The request user pool
	UserPool *string `json:"user_pool,omitempty"`
}

// Validate validates this auth request
func (m *AuthRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAudience(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateClientID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCodeChallenge(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCodeChallengeMethod(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRedirectURI(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateScope(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AuthRequest) validateAudience(formats strfmt.Registry) error {

	if err := validate.RequiredString("audience", "body", string(m.Audience)); err != nil {
		return err
	}

	return nil
}

func (m *AuthRequest) validateClientID(formats strfmt.Registry) error {

	if err := validate.RequiredString("client_id", "body", string(m.ClientID)); err != nil {
		return err
	}

	return nil
}

func (m *AuthRequest) validateCodeChallenge(formats strfmt.Registry) error {

	if err := validate.RequiredString("code_challenge", "body", string(m.CodeChallenge)); err != nil {
		return err
	}

	return nil
}

var authRequestTypeCodeChallengeMethodPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["S256"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		authRequestTypeCodeChallengeMethodPropEnum = append(authRequestTypeCodeChallengeMethodPropEnum, v)
	}
}

const (

	// AuthRequestCodeChallengeMethodS256 captures enum value "S256"
	AuthRequestCodeChallengeMethodS256 string = "S256"
)

// prop value enum
func (m *AuthRequest) validateCodeChallengeMethodEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, authRequestTypeCodeChallengeMethodPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *AuthRequest) validateCodeChallengeMethod(formats strfmt.Registry) error {

	if swag.IsZero(m.CodeChallengeMethod) { // not required
		return nil
	}

	// value enum
	if err := m.validateCodeChallengeMethodEnum("code_challenge_method", "body", m.CodeChallengeMethod); err != nil {
		return err
	}

	return nil
}

func (m *AuthRequest) validateRedirectURI(formats strfmt.Registry) error {

	if err := validate.RequiredString("redirect_uri", "body", string(m.RedirectURI)); err != nil {
		return err
	}

	return nil
}

func (m *AuthRequest) validateScope(formats strfmt.Registry) error {

	if swag.IsZero(m.Scope) { // not required
		return nil
	}

	if err := m.Scope.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("scope")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *AuthRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AuthRequest) UnmarshalBinary(b []byte) error {
	var res AuthRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// Value returns AuthRequest as a value that can be stored as json in the database
func (m AuthRequest) Value() (driver.Value, error) {
	return json.Marshal(m)
}

// Scan reads a json value from the database into a AuthRequest
func (m *AuthRequest) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New(http.StatusInternalServerError, "type assertion to []byte failed")
	}

	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}

	return nil
}
