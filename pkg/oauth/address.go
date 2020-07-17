// Code generated by go-swagger; DO NOT EDIT.

package oauth

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// Address OpenID address claim as defined in section 5.1.1 of the connect core 1.0 specification
//
// swagger:model Address
type Address struct {

	// Country name component.
	Country *string `json:"country,omitempty"`

	// Full mailing address, formatted for display or use on a mailing label. This field MAY contain multiple lines, separated by newlines.
	// Newlines can be represented either as a carriage return/line feed pair ("\r\n") or as a single line feed character ("\n").
	//
	Formatted *string `json:"formatted,omitempty"`

	// City or locality component.
	Locality *string `json:"locality,omitempty"`

	// Zip code or postal code component.
	PostalCode *string `json:"postal_code,omitempty"`

	// State, province, prefecture, or region component.
	Region *string `json:"region,omitempty"`

	// Full street address component, which MAY include house number, street name, Post Office Box, and multi-line extended street address
	// information. This field MAY contain multiple lines, separated by newlines. Newlines can be represented either as a carriage return/line
	// feed pair ("\r\n") or as a single line feed character ("\n").
	//
	StreetAddress *string `json:"street_address,omitempty"`
}

// Validate validates this address
func (m *Address) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *Address) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Address) UnmarshalBinary(b []byte) error {
	var res Address
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}