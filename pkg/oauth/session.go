/*
 * Copyright (C) 2020 Atomic Media Foundation
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file in the root of this
 * workspace for details.
 */

package oauth

import (
	"database/sql/driver"
	"encoding/json"
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// Session A Session is a browser based session object that stores the currently authenticate user principal
type Session struct {

	// The client that created the user session
	ClientID string `json:"client_id,omitempty"`

	// The token creation time
	CreatedAt int64 `json:"created_at,omitempty"`

	// The token expiration time
	ExpiresAt int64 `json:"expires_at,omitempty"`

	// The session id
	ID string `json:"id,omitempty"`

	// Subject is the user subject id
	Subject string `json:"subject,omitempty"`
}

// Validate validates this session
func (m *Session) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *Session) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Session) UnmarshalBinary(b []byte) error {
	var res Session
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// Value returns Session as a value that can be stored as json in the database
func (m Session) Value() (driver.Value, error) {
	return json.Marshal(m)
}

// Scan reads a json value from the database into a Session
func (m *Session) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New(http.StatusInternalServerError, "type assertion to []byte failed")
	}

	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}

	return nil
}
