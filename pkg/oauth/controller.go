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

// Package oauth provides the base auth interfaces
package oauth

import (
	"context"
	"net/http"
)

type (
	// Controller is the interface implemented by consumers of the auth server
	// This provides the backend functionality for user, application, and audience management
	Controller interface {
		// AudienceGet should return an audience for the specified name/id
		AudienceGet(ctx context.Context, name string) (Audience, error)

		// ApplicationGet should return an application for the specified client id
		ApplicationGet(ctx context.Context, clientID string) (*Application, error)

		// UserGet returns a user by subject id along with the underlying principal
		UserGet(ctx context.Context, id string) (*User, interface{}, error)

		// UserAuthenticate authenticates a user using the login and password
		// This function should return an oauth user and the principal
		UserAuthenticate(ctx context.Context, login string, password string) (*User, interface{}, error)

		// UserCreate will create the user, optionally validating the invite code
		UserCreate(ctx context.Context, login string, password string, profile *Profile, invite ...string) (*User, error)

		// UserUpdate updates a user profile
		UserUpdate(ctx context.Context, id string, profile *Profile) error

		// UserNotify should create an email or sms with the verification link or code for the user
		UserNotify(ctx context.Context, note Notification) error

		// UserResetPassword should notify the user with a reset password link to the
		// which includes the user's password reset code i.e.:
		// - https://domain.tld/setPassword?code={reset_code}
		//
		// These values should be the posted along with the new password to `/oauth/passwordSet`
		UserResetPassword(ctx context.Context, login string, resetCode string) error

		// UserSetPassword will set a user's password
		UserSetPassword(ctx context.Context, sub string, password string) error

		// TokenFinalize finalizes the token, signs it and returns the bearer
		TokenFinalize(ctx context.Context, claims Claims) (string, error)

		// TokenValidate validate the token signature and parse it into the Claims
		TokenValidate(ctx context.Context, bearerToken string) (Claims, error)
	}

	// CodeStore defines an AuthCode storage interface
	// AuthCodes are used by the Oauth 2.0 `authorization_code` flow
	CodeStore interface {
		// AuthCodeCreate creates a new authcode from the request if code expires at is set
		// the store should use that value, otherwise set the defaults
		AuthCodeCreate(context.Context, *AuthCode) error

		// AuthCodeGet returns a code from the store
		AuthCodeGet(context.Context, string) (*AuthCode, error)

		// AuthCodeDestroy removes a code from the store
		AuthCodeDestroy(context.Context, string) error
	}

	// SessionStore provides session persistence for oauth user flows
	SessionStore interface {
		// SessionCreate creates a new session, overwriting an exising session
		SessionCreate(context.Context, *http.Request) (Session, error)

		// SessionRead returns the session
		SessionRead(context.Context, *http.Request) (Session, error)

		// SessionDestroy should cleanup an session in the response
		SessionDestroy(context.Context, http.ResponseWriter, *http.Request) error
	}
)
