/*
 * Copyright (C) 2020 Atomic Media Foundation
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file in the root of this
 * workspace for details.
 */

package oauth

import "errors"

var (
	// ErrAccessDenied is returned when authentication has failed
	ErrAccessDenied = errors.New("access denied")

	// ErrCodeNotFound is returned when the store could not find the code
	ErrCodeNotFound = errors.New("code not found")

	// ErrApplicationNotFound is returned when the store could not find the application
	ErrApplicationNotFound = errors.New("application not found")

	// ErrAudienceNotFound is returned when the store could not find the audience
	ErrAudienceNotFound = errors.New("audience not found")

	// ErrSessionNotFound is returned when the session was not found by the controller
	ErrSessionNotFound = errors.New("session not found")

	// ErrUnsupportedAlogrithm is returned when the Authorizer gets a bad token
	ErrUnsupportedAlogrithm = errors.New("unsupported signing algorithm")

	// ErrInvalidToken is returned when the token is not valid
	ErrInvalidToken = errors.New("invalid token")

	// ErrPasswordLen is returned when a password does not meet length requirements
	ErrPasswordLen = errors.New("invalid password length")

	// ErrPasswordComplexity is returned if the password does not meet complexity requirements
	ErrPasswordComplexity = errors.New("password to simple")

	// ErrPasswordResuse is returned if password does not meet the reuse constraints
	ErrPasswordResuse = errors.New("password to reused")

	// ErrPasswordExpired is returned when the password has expired
	ErrPasswordExpired = errors.New("password expired")

	// ErrInvalidInviteCode is returned when an invitation code is bad
	ErrInvalidInviteCode = errors.New("bad invite code")
)
