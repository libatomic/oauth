/*
 * This file is part of the Atomic Stack (https://github.com/libatomic/atomic).
 * Copyright (c) 2020 Atomic Publishing.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package oauth

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

// Profile A profile object based on the [openid connect standard](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims).
//
//
// swagger:model Profile
type Profile struct {

	// Subject - Identifier for the End-User at the Issuer.
	//
	Subject string `json:"sub,omitempty"`

	// address
	Address *Address `json:"address,omitempty"`

	// End-User's birthday, represented as an ISO 8601:2004 [ISO8601‑2004] YYYY-MM-DD format. The year MAY be 0000, indicating that it is omitted.
	// To represent only the year, YYYY format is allowed. Note that depending on the underlying platform's date related function, providing just
	// year can result in varying month and day, so the implementers need to take this factor into account to correctly process the dates."
	//
	// Format: date
	Birthdate *strfmt.Date `json:"birthdate,omitempty"`

	// The user's email address
	// Format: email
	Email strfmt.Email `json:"email,omitempty"`

	// True if the End-User's e-mail address has been verified; otherwise false. When this Claim Value is true, this means that the OP
	// took affirmative steps to ensure that this e-mail address was controlled by the End-User at the time the verification was performed.
	// The means by which an e-mail address is verified is context-specific, and dependent upon the trust framework or contractual agreements
	// within which the parties are operating.
	//
	EmailVerified *bool `json:"email_verified,omitempty"`

	// Surname(s) or last name(s) of the End-User. Note that in some cultures, people can have multiple family names or no family name;
	// all can be present, with the names being separated by space characters.
	//
	FamilyName string `json:"family_name,omitempty"`

	// End-User's gender. Values defined by this specification are female and male. Other values MAY be used when neither
	// of the defined values are applicable.
	//
	Gender string `json:"gender,omitempty"`

	// Given name(s) or first name(s) of the End-User. Note that in some cultures, people can have multiple given names;
	// all can be present, with the names being separated by space characters.
	//
	GivenName string `json:"given_name,omitempty"`

	// End-User's locale, represented as a BCP47 [RFC5646] language tag. This is typically an ISO 639-1 Alpha-2 [ISO639‑1] language code in lowercase
	// and an ISO 3166-1 Alpha-2 [ISO3166‑1] country code in uppercase, separated by a dash. For example, en-US or fr-CA. As a compatibility note,
	// some implementations have used an underscore as the separator rather than a dash, for example, en_US; Relying Parties MAY choose to accept
	// this locale syntax as well.
	//
	Locale *string `json:"locale,omitempty"`

	// Middle name(s) of the End-User. Note that in some cultures, people can have multiple middle names;
	// all can be present, with the names being separated by space characters. Also note that in some cultures, middle names are not used.
	//
	MiddleName string `json:"middle_name,omitempty"`

	// End-User's full name in displayable form including all name parts, possibly including titles and suffixes,
	// ordered according to the End-User's locale and preferences.
	//
	Name string `json:"name,omitempty"`

	// Casual name of the End-User that may or may not be the same as the given_name. For instance,
	// a nickname value of Mike might be returned alongside a given_name value of Michael.
	//
	Nickname string `json:"nickname,omitempty"`

	// The user's phone number in E.164 format
	PhoneNumber *string `json:"phone_number,omitempty"`

	// True if the End-User's phone number has been verified; otherwise false. When this Claim Value is true, this means that the OP
	// took affirmative steps to ensure that this phone number was controlled by the End-User at the time the verification was performed.
	// The means by which a phone number is verified is context-specific, and dependent upon the trust framework or contractual agreements
	// within which the parties are operating. When true, the phone_number Claim MUST be in E.164 format and any extensions MUST be
	// represented in RFC 3966 format."
	//
	PhoneNumberVerified bool `json:"phone_number_verified,omitempty"`

	// URL of the End-User's profile picture. This URL MUST refer to an image file (for example, a PNG, JPEG, or GIF image file),
	// rather than to a Web page containing an image. Note that this URL SHOULD specifically reference a profile photo of the
	// End-User suitable for displaying when describing the End-User, rather than an arbitrary photo taken by the End-User.
	//
	Picture string `json:"picture,omitempty"`

	// Shorthand name by which the End-User wishes to be referred to at the RP, such as janedoe or j.doe. This value MAY be any valid
	// JSON string including special characters such as @, /, or whitespace. The RP MUST NOT rely upon this value being unique.
	//
	PreferredUsername string `json:"preferred_username,omitempty"`

	// URL of the End-User's profile page. The contents of this Web page SHOULD be about the End-User.
	//
	// Format: uri
	Profile strfmt.URI `json:"profile,omitempty"`

	// Time the End-User's information was last updated. Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z
	// as measured in UTC until the date/time.
	//
	UpdatedAt int64 `json:"updated_at,omitempty"`

	// URL of the End-User's Web page or blog. This Web page SHOULD contain information published by the End-User or an
	// organization that the End-User is affiliated with.
	//
	Website string `json:"website,omitempty"`

	// String from zoneinfo [zoneinfo] time zone database representing the End-User's time zone. For example, Europe/Paris or America/Los_Angeles.
	//
	Zoneinfo string `json:"zoneinfo,omitempty"`
}

// Validate validates this profile
func (m *Profile) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAddress(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateBirthdate(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEmail(formats); err != nil {
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

func (m *Profile) validateAddress(formats strfmt.Registry) error {

	if swag.IsZero(m.Address) { // not required
		return nil
	}

	if m.Address != nil {
		if v, ok := interface{}(m.Address).(runtime.Validatable); ok {
			if err := v.Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("address")
				}
				return err
			}
		}
	}

	return nil
}

func (m *Profile) validateBirthdate(formats strfmt.Registry) error {

	if swag.IsZero(m.Birthdate) { // not required
		return nil
	}

	if err := validate.FormatOf("birthdate", "body", "date", m.Birthdate.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *Profile) validateEmail(formats strfmt.Registry) error {

	if swag.IsZero(m.Email) { // not required
		return nil
	}

	if err := validate.FormatOf("email", "body", "email", m.Email.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *Profile) validateProfile(formats strfmt.Registry) error {

	if swag.IsZero(m.Profile) { // not required
		return nil
	}

	if err := validate.FormatOf("profile", "body", "uri", m.Profile.String(), formats); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *Profile) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Profile) UnmarshalBinary(b []byte) error {
	var res Profile
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// Value returns Profile as a value that can be stored as json in the database
func (m Profile) Value() (driver.Value, error) {
	return json.Marshal(m)
}

// Scan reads a json value from the database into a Profile
func (m *Profile) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New(http.StatusInternalServerError, "type assertion to []byte failed")
	}

	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}

	return nil
}
