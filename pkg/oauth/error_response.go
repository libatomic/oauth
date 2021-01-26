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
)

// ErrorResponse A common error response
//
// swagger:model ErrorResponse
type ErrorResponse struct {

	// The error message
	// Required: true
	Message string `json:"message"`
}

// Value returns ErrorResponse as a value that can be stored as json in the database
func (m ErrorResponse) Value() (driver.Value, error) {
	return json.Marshal(m)
}

// Scan reads a json value from the database into a ErrorResponse
func (m *ErrorResponse) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New(http.StatusInternalServerError, "type assertion to []byte failed")
	}

	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}

	return nil
}
