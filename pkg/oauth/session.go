/*
 * Copyright (C) 2020 Atomic Media Foundation
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file in the root of this
 * workspace for details.
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
