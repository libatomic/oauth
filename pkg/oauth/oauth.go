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
