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
	"github.com/go-openapi/swag"
)

// AuthCode Authcodes are used by client in browser based flows to request BearerTokens
//
// Internally Authcodes are associated with an AuthRequest, which are not
// persisted until after authentication has completed successfully.
//
// Additionally, the library uses AuthCodes to:
//   - store refresh tokens used when a client request offline_access.
//   - reset user passwords
//
//
type AuthCode struct {
	AuthRequest

	// The auth code value provided by the CodeStore
	Code string `json:"code,omitempty"`

	// The time the code was issued on
	IssuedAt int64 `json:"issued_at,omitempty"`

	// The refresh token nonce
	RefreshNonce string `json:"refresh_nonce,omitempty"`

	// The session id
	SessionID string `json:"session_id,omitempty"`

	// The session subject
	Subject string `json:"subject,omitempty"`

	// If this is false the session was created in am SSO flow without capture user credentials
	// Some audiences may request credentials
	//
	UserAuthenticated bool `json:"user_authenticated,omitempty"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (m *AuthCode) UnmarshalJSON(raw []byte) error {
	// AO0
	var aO0 AuthRequest
	if err := swag.ReadJSON(raw, &aO0); err != nil {
		return err
	}
	m.AuthRequest = aO0

	// AO1
	var dataAO1 struct {
		Code string `json:"code,omitempty"`

		IssuedAt int64 `json:"issued_at,omitempty"`

		RefreshNonce string `json:"refresh_nonce,omitempty"`

		SessionID string `json:"session_id,omitempty"`

		Subject string `json:"subject,omitempty"`

		UserAuthenticated bool `json:"user_authenticated,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataAO1); err != nil {
		return err
	}

	m.Code = dataAO1.Code

	m.IssuedAt = dataAO1.IssuedAt

	m.RefreshNonce = dataAO1.RefreshNonce

	m.SessionID = dataAO1.SessionID

	m.Subject = dataAO1.Subject

	m.UserAuthenticated = dataAO1.UserAuthenticated

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (m AuthCode) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	aO0, err := swag.WriteJSON(m.AuthRequest)
	if err != nil {
		return nil, err
	}
	_parts = append(_parts, aO0)
	var dataAO1 struct {
		Code string `json:"code,omitempty"`

		IssuedAt int64 `json:"issued_at,omitempty"`

		RefreshNonce string `json:"refresh_nonce,omitempty"`

		SessionID string `json:"session_id,omitempty"`

		Subject string `json:"subject,omitempty"`

		UserAuthenticated bool `json:"user_authenticated,omitempty"`
	}

	dataAO1.Code = m.Code

	dataAO1.IssuedAt = m.IssuedAt

	dataAO1.RefreshNonce = m.RefreshNonce

	dataAO1.SessionID = m.SessionID

	dataAO1.Subject = m.Subject

	dataAO1.UserAuthenticated = m.UserAuthenticated

	jsonDataAO1, errAO1 := swag.WriteJSON(dataAO1)
	if errAO1 != nil {
		return nil, errAO1
	}
	_parts = append(_parts, jsonDataAO1)
	return swag.ConcatJSON(_parts...), nil
}

// Value returns AuthCode as a value that can be stored as json in the database
func (m AuthCode) Value() (driver.Value, error) {
	return json.Marshal(m)
}

// Scan reads a json value from the database into a AuthCode
func (m *AuthCode) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New(http.StatusInternalServerError, "type assertion to []byte failed")
	}

	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}

	return nil
}
