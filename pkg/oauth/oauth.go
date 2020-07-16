/*
 * Copyright (C) 2020 Atomic Media Foundation
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file in the root of this
 * workspace for details.
 */

// Package oauth provides the base auth interfaces
package oauth

import (
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

const (
	// ScopeOpenID is the scope that provides identity tokens
	ScopeOpenID = "openid"

	// ScopeProfile is the scope that provides profile claims in the identity token
	ScopeProfile = "profile"

	// ScopeOffline is the scope that allows a client to request refresh tokens
	ScopeOffline = "offline_access"

	// GrantTypeAuthCode is the auth code grant type
	GrantTypeAuthCode = "authorization_code"

	// GrantTypeRefreshToken is the refresh token offline_access token type
	GrantTypeRefreshToken = "refresh_token"

	// GrantTypeClientCredentials is the grant for machine-to-machine access
	GrantTypeClientCredentials = "client_credentials"
)

type (
	// Controller is the interface implemented by consumers of the auth server
	Controller interface {
		// ApplicationGet should return an application for the specified client id
		ApplicationGet(id string) (*Application, error)

		// AudienceGet should return an audience for the specified name
		AudienceGet(name string) (*Audience, error)

		// UserGet returns a user by subject id
		UserGet(id string) (*User, error)

		// UserAuthenticate authenticates a user using the login and password
		// This function should return the user object or error
		UserAuthenticate(login string, password string) (*User, error)

		// UserCreate will create the user, optionally validating the invite code
		UserCreate(user *User, password string, invite ...string) error

		// UserVerify will verify the user's email address
		UserVerify(id string, code string) error
	}

	// Authorizer provides an interface for authorizing bearer tokens
	// The Authorizer should ensure the scope and should return the token with jwt.MapClaims
	// The first return value is the token, the second is the princial (*User or *Application)
	Authorizer interface {
		AuthorizeRequest(r *http.Request, scope ...[]string) (*jwt.Token, interface{}, error)
	}

	// CodeStore defines an AuthCode storage interface
	// AuthCodes are used by the Oauth 2.0 `authorization_code` flow
	CodeStore interface {
		// CodeCreate creates a new authcode from the request if code expires at is set
		// the store should use that value, otherwise set the defaults
		CodeCreate(req *AuthCode) error

		// CodeGet returns a code from the store
		CodeGet(code string) (*AuthCode, error)

		// CodeDestroy removes a code from the store
		CodeDestroy(code string) error
	}
)
