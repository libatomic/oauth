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

package server

import (
	"fmt"
	"net/url"

	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/oauth/pkg/oauth"
)

type (
	// RedirectError defines a redirect error handler
	RedirectError func(u *url.URL) api.Responder

	ErrorResponder struct {
		api.Responder
		err error
	}
)

var (
	// ErrMissingParameter is returned when a parameter is missing
	ErrMissingParameter = func(u *url.URL, param string) api.Responder {
		msg := fmt.Sprintf("parameter %s is a required", param)

		if u == nil {
			return oauth.Errorf(oauth.ErrorCodeInvalidRequest, msg)
		}

		return api.Redirect(u, map[string]string{
			"error":             string(oauth.ErrorCodeInvalidRequest),
			"error_description": msg,
		})
	}

	// ErrInvalidParameter is returned when a parameter is valid
	ErrInvalidParameter = func(u *url.URL, param string) api.Responder {
		msg := fmt.Sprintf("parameter %s is not valid", param)

		if u == nil {
			return oauth.Errorf(oauth.ErrorCodeInvalidRequest, msg)
		}

		return api.Redirect(u, map[string]string{
			"error":             string(oauth.ErrorCodeInvalidRequest),
			"error_description": msg,
		})
	}

	// ErrInvalidContext is returned when the context can not be resolved
	ErrInvalidContext = func(u *url.URL) api.Responder {
		msg := fmt.Sprintf("invalid context")

		if u == nil {
			return oauth.Errorf(oauth.ErrorCodeInvalidRequest, msg)
		}

		return api.Redirect(u, map[string]string{
			"error":             string(oauth.ErrorCodeInvalidRequest),
			"error_description": msg,
		})
	}

	// ErrExpiredRequestToken is returned when the token is expired
	ErrExpiredRequestToken = func(u *url.URL) api.Responder {
		msg := fmt.Sprintf("request token expired")

		if u == nil {
			return oauth.Errorf(oauth.ErrorCodeAccessDenied, msg)
		}

		return api.Redirect(u, map[string]string{
			"error":             string(oauth.ErrorCodeAccessDenied),
			"error_description": msg,
		})
	}

	// ErrUserNotFound is returned when the user is not found
	ErrUserNotFound = func(u *url.URL) api.Responder {
		msg := fmt.Sprintf("user not found")

		if u == nil {
			return oauth.Errorf(oauth.ErrorCodeAccessDenied, msg)
		}

		return api.Redirect(u, map[string]string{
			"error":             string(oauth.ErrorCodeAccessDenied),
			"error_description": msg,
		})
	}

	// ErrUnauthorizedRediretURI is returned when the redirect uri is not authorized
	ErrUnauthorizedRediretURI = func(u *url.URL) api.Responder {
		msg := fmt.Sprintf("unauthorized redirect uri")

		if u == nil {
			return oauth.Errorf(oauth.ErrorCodeAccessDenied, msg)
		}

		return api.Redirect(u, map[string]string{
			"error":             string(oauth.ErrorCodeAccessDenied),
			"error_description": msg,
		})
	}

	// ErrUnauthorized is returned when the request has been denied
	ErrUnauthorized = func(u *url.URL, reason string) api.Responder {
		msg := fmt.Sprintf("unauthorized request: %s", reason)

		if u == nil {
			return oauth.Errorf(oauth.ErrorCodeAccessDenied, msg)
		}

		return api.Redirect(u, map[string]string{
			"error":             string(oauth.ErrorCodeAccessDenied),
			"error_description": msg,
		})
	}

	// ErrBadRequest is used for invalid requests
	ErrBadRequest = func(u *url.URL, reason string) api.Responder {
		msg := fmt.Sprintf("bad request: %s", reason)

		if u == nil {
			return oauth.Errorf(oauth.ErrorCodeInvalidRequest, msg)
		}

		return api.Redirect(u, map[string]string{
			"error":             string(oauth.ErrorCodeInvalidRequest),
			"error_description": msg,
		})
	}

	// ErrServerError is used for internal errors
	ErrServerError = func(u *url.URL, f string, args ...interface{}) api.Responder {
		msg := fmt.Sprintf(f, args...)

		if u == nil {
			return oauth.Errorf(oauth.ErrorCodeServerError, msg)
		}

		return api.Redirect(u, map[string]string{
			"error":             string(oauth.ErrorCodeServerError),
			"error_description": msg,
		})
	}
)

func (e ErrorResponder) Error() string {
	return e.err.Error()
}
