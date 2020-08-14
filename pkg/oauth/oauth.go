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
	"github.com/dgrijalva/jwt-go"
	"github.com/libatomic/api/pkg/api"
)

const (
	// ScopeOpenID is the scope that provides identity tokens
	ScopeOpenID = "openid"

	// ScopeProfile is the scope that provides profile claims in the identity token
	ScopeProfile = "profile"

	// ScopePrincipal is the scope that provides principal claims in the identity token
	ScopePrincipal = "principal"

	// ScopeOffline is the scope that allows a client to request refresh tokens
	ScopeOffline = "offline_access"

	// GrantTypeAuthCode is the auth code grant type
	GrantTypeAuthCode = "authorization_code"

	// GrantTypeRefreshToken is the refresh token offline_access token type
	GrantTypeRefreshToken = "refresh_token"

	// GrantTypeClientCredentials is the grant for machine-to-machine access
	GrantTypeClientCredentials = "client_credentials"

	// GrantTypePassword is the grant password grants
	GrantTypePassword = "password"
)

type (
	// Context provides the oauth user and underlying principal from the authorizer
	Context interface {
		// Application is the client for the context
		Application() *Application

		// Audience is the context audience
		Audience() *Audience

		// User is the oauth user for the context
		User() *User

		// Token is the oauth token object
		Token() *jwt.Token

		// Request provides the auth request
		Request() *AuthRequest

		// Prinicipal is the implementor opaque principal
		Principal() interface{}
	}

	// Controller is the interface implemented by consumers of the auth server
	Controller interface {
		// ApplicationGet should return an application for the specified client id
		ApplicationGet(id string) (*Application, error)

		// AudienceGet should return an audience for the specified name
		AudienceGet(name string) (*Audience, error)

		// UserGet returns a user by subject id along with the underlying principal
		UserGet(ctx Context, id string) (*User, interface{}, error)

		// UserAuthenticate authenticates a user using the login and password
		// This function should return an oauth user and the principal
		UserAuthenticate(ctx Context, login string, password string) (*User, interface{}, error)

		// UserCreate will create the user, optionally validating the invite code
		// This method should send the user an email verification link with the format:
		// - https://domain.tld/oauth/verify?sub={user_id}&code={verify_code}&redirect_uri=/
		//
		// The library will call the controller's UserVerify method with this id and code
		UserCreate(ctx Context, user *User, password string, invite ...string) error

		// UserVerify should validate the code and update the user's email address as verified
		UserVerify(ctx Context, id string, code string) error

		// UserUpdate updates a user
		UserUpdate(ctx Context, user *User) error

		// UserResetPassword should notify the user with a reset password link to the
		// which includes the user's password reset code i.e.:
		// - https://domain.tld/setPassword?code={reset_code}
		//
		// These values should be the posted along with the new password to `/oauth/passwordSet`
		UserResetPassword(ctx Context, login string, resetCode string) error

		// UserSetPassword will set a user's password
		UserSetPassword(ctx Context, id string, password string) error

		// TokenFinalize finalizes the scope prior to signing
		TokenFinalize(ctx Context, scope Permissions, claims map[string]interface{})
	}

	// Authorizer is an oauth authorizer interface
	Authorizer func(scope ...Permissions) api.Authorizer

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
