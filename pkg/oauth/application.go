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

// Application Applications are API clients that access APIs managed by the integration
// service. Applications may provide user authentication flows.
// Applications are managed by the `oauth.Controller`. This library provides
// an incomplete base definition for application clients.
//
// ## API URLs
// This is an array of the application's allowed application uris. These are checked
// in the `/authorize` path to ensure the redirect is allowed by the application.
// This path on redirect will receive the following query parameters:
//
//   - `auth_request`: An encoded and signed request value to be forwarded to various posts.
//
// ## Redirect URIs
// This is an array of the application's allowed redirect uris. These are checked
// in the `/login` path to ensure the redirect is allowed by the application.
// This path on redirect will receive the following query parameters:
type (
	Application struct {

		// allowed grants
		AllowedGrants PermissionSet `json:"allowed_grants,omitempty"`

		// app uris
		AppUris PermissionSet `json:"app_uris,omitempty"`

		// The application client id used for oauth grants
		// Read Only: true
		ClientID string `json:"client_id,omitempty"`

		// The application client secret used for oauth grants
		// Read Only: true
		ClientSecret string `json:"client_secret,omitempty"`

		// The application description
		Description *string `json:"description,omitempty"`

		// The application name
		Name string `json:"name,omitempty"`

		// permissions
		Permissions PermissionSet `json:"permissions,omitempty"`

		// redirect uris
		RedirectUris PermissionSet `json:"redirect_uris,omitempty"`

		// The lifetime for identity tokens in seconds, provided the call requested the
		// `openid` scopes.
		//
		TokenLifetime int64 `json:"token_lifetime,omitempty"`

		// The application type
		// Enum: [web native machine]
		Type string `json:"type,omitempty"`
	}
)

// Value returns Application as a value that can be stored as json in the database
func (m Application) Value() (driver.Value, error) {
	return json.Marshal(m)
}

// Scan reads a json value from the database into a Application
func (m *Application) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New(http.StatusInternalServerError, "type assertion to []byte failed")
	}

	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}

	return nil
}
