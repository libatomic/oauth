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
	"time"

	"github.com/go-openapi/errors"
)

// User A user is a user object
type (
	User struct {

		// The user's login
		//
		// Required: true
		Login string `json:"login"`

		// The time the user password expirts
		// Format: date-time
		PasswordExpiresAt time.Time `json:"password_expires_at,omitempty"`

		// permissions
		Permissions PermissionSet `json:"permissions,omitempty"`

		// profile
		Profile *Profile `json:"profile,omitempty"`

		// roles
		Roles PermissionSet `json:"roles,omitempty"`
	}
)

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
