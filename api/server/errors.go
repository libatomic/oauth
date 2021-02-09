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
	"net/http"
	"net/url"

	"github.com/libatomic/api/pkg/api"
)

type (
	// RedirectError defines a redirect error handler
	RedirectError func(u *url.URL) api.Responder
)

var (
	// ErrMissingParameter is returned when a parameter is missing
	ErrMissingParameter = func(u *url.URL, param string) api.Responder {
		return api.ErrorRedirect(u, http.StatusBadRequest, "%s required", param)
	}

	// ErrInvalidParameter is returned when a parameter is valid
	ErrInvalidParameter = func(u *url.URL, param string) api.Responder {
		return api.ErrorRedirect(u, http.StatusBadRequest, "%s is not valid", param)
	}

	// ErrInvalidContext is returned when the context can not be resolved
	ErrInvalidContext = func(u *url.URL) api.Responder {
		return api.ErrorRedirect(u, http.StatusForbidden, "invalid context")
	}

	// ErrExpiredRequestToken is returned when the token is expired
	ErrExpiredRequestToken = func(u *url.URL) api.Responder {
		return api.ErrorRedirect(u, http.StatusUnauthorized, "request token is expired")
	}

	// ErrUserNotFound is returned when the user is not found
	ErrUserNotFound = func(u *url.URL) api.Responder {
		return api.ErrorRedirect(u, http.StatusUnauthorized, "user does not exist")
	}

	// ErrUnauthorizedRediretURI is returned when the redirect uri is not authorized
	ErrUnauthorizedRediretURI = func(u *url.URL) api.Responder {
		return api.ErrorRedirect(u, http.StatusForbidden, "unauthorized redirect_uri")
	}
)
