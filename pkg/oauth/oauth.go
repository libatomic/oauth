/*
 * Copyright (C) 2020 Atomic Media Foundation
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file in the root of this
 * workspace for details.
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
