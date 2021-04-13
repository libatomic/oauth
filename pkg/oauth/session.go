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
	"net/http"
	"time"
)

type (
	// Session A Session is interface for browser based sessions
	Session interface {
		// ID is the session id
		ID() string

		// ClientID is the client that created the user session
		ClientID() string

		// Audience is the session audience
		Audience() string

		// Subject is the user subject id
		Subject() string

		// Scope is the session scope
		Scope(aud string) Permissions

		// CreatedAt is the session creation time
		CreatedAt() time.Time

		// ExpiresAt is the session expriation time
		ExpiresAt() time.Time

		// Set sets a value in the session interface
		Set(key string, value interface{})

		// Get gets a value from the session interface
		Get(key string) interface{}

		// Write writes the session to the response
		Write(http.ResponseWriter) error

		// Destroy clears the session from the response
		Destroy(http.ResponseWriter) error
	}
)
