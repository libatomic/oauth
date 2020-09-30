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
	"context"
	"crypto/rsa"
	"net/http"
)

type (
	// Controller is the interface implemented by consumers of the auth server
	// This provides the backend functionality for user, application, and audience management
	Controller interface {
		CodeStore

		SessionController

		// AudienceGet should return an audience for the specified name
		AudienceGet(context.Context, string) (*Audience, error)

		// ApplicationGet should return an application for the specified client id
		ApplicationGet(context.Context, string) (*Application, error)

		// UserGet returns a user by subject id along with the underlying principal
		UserGet(Context, string) (*User, interface{}, error)

		// TokenPublicKey returns the key for the specified context which is used to verify tokens
		TokenPublicKey(ctx Context) (*rsa.PublicKey, error)

		// UserAuthenticate authenticates a user using the login and password
		// This function should return an oauth user and the principal
		UserAuthenticate(ctx Context, login string, password string) (*User, interface{}, error)

		// UserCreate will create the user, optionally validating the invite code
		// This method should send the user an email verification link with the format:
		// - https://domain.tld/oauth/verify?sub={user_id}&code={verify_code}&redirect_uri=/
		//
		// The library will call the controller's UserVerify method with this id and code
		UserCreate(ctx Context, user User, password string, invite ...string) (*User, error)

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

		// TokenPrivateKey returns the key for the specified context which is used to sign tokens
		TokenPrivateKey(ctx Context) (*rsa.PrivateKey, error)

		// AuthorizedGrantTypes returns the list of grant types the controller with authorize
		AuthorizedGrantTypes(ctx Context) Permissions
	}

	// CodeStore defines an AuthCode storage interface
	// AuthCodes are used by the Oauth 2.0 `authorization_code` flow
	CodeStore interface {
		// AuthCodeCreate creates a new authcode from the request if code expires at is set
		// the store should use that value, otherwise set the defaults
		AuthCodeCreate(Context, *AuthCode) error

		// AuthCodeGet returns a code from the store
		AuthCodeGet(Context, string) (*AuthCode, error)

		// AuthCodeDestroy removes a code from the store
		AuthCodeDestroy(Context, string) error
	}

	// SessionController provides session persistence for oauth user flows
	SessionController interface {
		// SessionCreate creates a session
		SessionCreate(Context, *Session) error

		// SessionGet gets a session by id
		SessionGet(Context, string) (*Session, error)

		// SessionUpdate updates a session
		SessionUpdate(Context, *Session) error

		// SessionDelete deletes a session from the store
		SessionDelete(Context, string) error

		// SessionRead retrieves the session from the request
		SessionRead(r *http.Request) (*Session, error)

		// SessionWrite writes a session to the response
		SessionWrite(Context, http.ResponseWriter, *Session) error

		// SessionDestroy destroys the session in the response
		SessionDestroy(Context, http.ResponseWriter, *http.Request) error
	}
)
