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
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/oauth/pkg/oauth"
	"github.com/mitchellh/mapstructure"
)

type (

	// TokenParams contains all the bound params for the token operation
	TokenParams struct {
		Audience        *string  `json:"audience,omitempty"`
		ClientID        *string  `json:"client_id"`
		ClientSecret    *string  `json:"client_secret,omitempty"`
		Code            *string  `json:"code,omitempty"`
		CodeVerifier    *string  `json:"code_verifier"`
		GrantType       string   `json:"grant_type"`
		Password        *string  `json:"password,omitempty"`
		RefreshNonce    *string  `json:"refresh_nonce,omitempty"`
		RefreshToken    *string  `json:"refresh_token,omitempty"`
		RefreshVerifier *string  `json:"refresh_verifier,omitempty"`
		Scope           []string `json:"scope,omitempty"`
		Username        *string  `json:"username,omitempty"`
	}

	// TokenIntrospectParams is the parameters for token introspect
	TokenIntrospectParams struct {
		Token string `json:"token"`
	}

	// TokenRevokeParams is the parameters for token revoke
	TokenRevokeParams struct {
		Token string `json:"token"`
	}
)

func init() {
	registerRoutes([]route{
		{"/token", http.MethodPost, &TokenParams{}, token, nil, nil},
		{"/token-introspect", http.MethodPost, &TokenIntrospectParams{}, tokenIntrospect, oauth.Scope(oauth.ScopeTokenRead), nil},
		{"/token-revoke", http.MethodPost, &TokenRevokeParams{}, tokenRevoke, oauth.Scope(oauth.ScopeTokenRevoke), nil},
	})
}

// Validate validate TokenParams
func (p TokenParams) Validate() error {
	err := validation.Errors{
		"audience":         validation.Validate(p.Audience, validation.NilOrNotEmpty),
		"client_id":        validation.Validate(p.ClientID, validation.When(p.Code == nil, validation.Required)),
		"client_secret":    validation.Validate(p.ClientSecret, validation.NilOrNotEmpty),
		"code":             validation.Validate(p.Code, validation.When(p.GrantType == oauth.GrantTypeAuthCode, validation.Required)),
		"code_verifier":    validation.Validate(p.CodeVerifier, validation.NilOrNotEmpty),
		"grant_type":       validation.Validate(p.GrantType, validation.Required),
		"password":         validation.Validate(p.Password, validation.NilOrNotEmpty),
		"refresh_nonce":    validation.Validate(p.RefreshNonce, validation.NilOrNotEmpty),
		"refresh_token":    validation.Validate(p.RefreshToken, validation.When(p.GrantType == oauth.GrantTypeRefreshToken, validation.Required)),
		"refresh_verifier": validation.Validate(p.RefreshVerifier, validation.NilOrNotEmpty),
		"scope":            validation.Validate(p.Scope, validation.NilOrNotEmpty),
		"username":         validation.Validate(p.Username, validation.NilOrNotEmpty),
	}.Filter()

	if err != nil {
		return &ErrorResponder{
			Responder: oauth.Error(oauth.ErrorCodeInvalidRequest, err),
			err:       err,
		}
	}

	return nil
}

func token(ctx context.Context, params *TokenParams) api.Responder {
	var code *oauth.AuthCode

	s := serverContext(ctx)

	if params.Audience == nil {
		aud := api.RequestHost(ctx)
		params.Audience = &aud
	}

	// ensure the audience
	aud, err := s.ctrl.AudienceGet(ctx, *params.Audience)
	if err != nil {
		return oauth.Errorf(oauth.ErrorCodeInvalidRequest, "audience lookup failed: %s", err)
	}
	ctx = oauth.NewContext(ctx, aud)

	if params.Code != nil {
		code, err = codeStore(ctx).AuthCodeGet(ctx, *params.Code)
		if err != nil {
			return oauth.Errorf(oauth.ErrorCodeInvalidGrant, "invalid authorization code")
		}

		if params.ClientID == nil {
			params.ClientID = &code.ClientID
		}
	}

	if params.ClientID == nil {
		return oauth.Errorf(oauth.ErrorCodeInvalidRequest, "client_id: cannot be blank")
	}

	// ensure this is a valid application
	app, err := s.ctrl.ApplicationGet(ctx, *params.ClientID)
	if err != nil {
		return oauth.Errorf(oauth.ErrorCodeInvalidClient, "application lookup failed: %s", err)
	}
	ctx = oauth.NewContext(ctx, app)

	if params.ClientSecret != nil && *params.ClientSecret != app.ClientSecret {
		return oauth.Errorf(oauth.ErrorCodeInvalidClient, "bad client secret")
	}

	bearer := &oauth.BearerToken{
		TokenType: "bearer",
	}

	if g, ok := app.AllowedGrants[aud.Name()]; !ok || !g.Contains(params.GrantType) {
		return oauth.Errorf(oauth.ErrorCodeUnauthorizedClient, "unauthorized grant")
	}

	// ensure the controller allows these grants
	if !s.allowedGrants.Contains(params.GrantType) {
		return oauth.Errorf(oauth.ErrorCodeUnauthorizedClient, "unauthorized grant")
	}

	// sanity check to ensure the audience actually has the permissions requested
	if !aud.Permissions().Every(params.Scope...) {
		return oauth.Errorf(oauth.ErrorCodeInvalidScope, "bad scope")
	}

	iss := issuer(ctx)

	var user *oauth.User

	switch params.GrantType {
	case oauth.GrantTypePassword:
		if *params.ClientID != app.ClientID {
			return oauth.Errorf(oauth.ErrorCodeInvalidClient, "client id mismatch")
		}
		if params.ClientSecret == nil {
			return oauth.Errorf(oauth.ErrorCodeInvalidClient, "client secret required")
		}

		if params.Username == nil || params.Password == nil {
			return oauth.Errorf(oauth.ErrorCodeInvalidClient, "bad credentials")
		}

		user, _, err = s.ctrl.UserAuthenticate(
			ctx,
			*params.Username,
			*params.Password,
		)
		if err != nil {
			return oauth.Error(oauth.ErrorCodeInvalidClient, err)
		}

		if len(params.Scope) == 0 {
			if perms, ok := user.Permissions[*params.Audience]; ok {
				params.Scope = perms
			}
		}
		fallthrough

	case oauth.GrantTypeClientCredentials:
		if params.ClientSecret == nil {
			return oauth.Errorf(oauth.ErrorCodeInvalidClient, "client secret required")
		}

		// ensure this app has these permissions
		perms, ok := app.Permissions[*params.Audience]
		if !ok || !perms.Every(params.Scope...) {
			return oauth.Errorf(oauth.ErrorCodeInvalidScope, "bad scope")
		}

		if len(params.Scope) == 0 {
			params.Scope = perms
		}

		claims := oauth.Claims{
			"use": "access",
		}

		exp := time.Now().Add(time.Second * time.Duration(aud.TokenLifetime())).Unix()

		if user != nil {
			claims["sub"] = user.Profile.Subject

			if roles, ok := user.Roles[aud.Name()]; ok {
				claims["roles"] = strings.Join(roles, " ")
			}
		} else {
			claims["sub"] = fmt.Sprintf("%s@applications", app.ClientID)
		}

		claims["aud"] = aud.Name()
		claims["exp"] = exp
		claims["iat"] = time.Now().Unix()
		claims["scope"] = strings.Join(params.Scope, " ")
		claims["iss"] = iss
		claims["azp"] = app.ClientID

		token, err := s.ctrl.TokenFinalize(ctx, claims)
		if err != nil {
			return oauth.Error(oauth.ErrorCodeServerError, err)
		}
		bearer.AccessToken = token
		bearer.ExpiresIn = int64(exp - time.Now().Unix())

	case oauth.GrantTypeRefreshToken:
		code, err = codeStore(ctx).AuthCodeGet(ctx, *params.RefreshToken)
		if err != nil {
			return oauth.Errorf(oauth.ErrorCodeInvalidGrant, "invalid refresh token")
		}

		if params.ClientSecret == nil {
			if params.RefreshToken == nil || params.RefreshVerifier == nil {
				return oauth.Errorf(oauth.ErrorCodeInvalidGrant, "missing refresh_verifier")
			}

			sum := sha256.Sum256([]byte(*params.RefreshVerifier))
			check := base64.RawURLEncoding.EncodeToString(sum[:])

			if code.RefreshNonce != check {
				return oauth.Errorf(oauth.ErrorCodeInvalidGrant, "refresh_verifier mismatch")
			}
		}

		if app.RefreshTokenMaxAge > 0 {
			issAt := time.Unix(code.IssuedAt, 0)

			maxAge := time.Hour * 24 * time.Duration(app.RefreshTokenMaxAge)

			if issAt.Add(maxAge).Before(time.Now()) {
				return oauth.Errorf(oauth.ErrorCodeInvalidGrant, "refresh token age limit exceeded")
			}
		}

		fallthrough

	case oauth.GrantTypeAuthCode:
		oauth.AuthContext(ctx).Request = &code.AuthRequest

		if code == nil {
			return oauth.Errorf(oauth.ErrorCodeInvalidRequest, "authorization code missing")
		}

		if code.CodeChallenge != nil { //&& strings.EqualFold(code.CodeChallengeMethod, "s256") {
			if params.CodeVerifier == nil {
				return oauth.Errorf(oauth.ErrorCodeInvalidGrant, "missing code_verifier")
			}

			sum := sha256.Sum256([]byte(*params.CodeVerifier))
			check := base64.RawURLEncoding.EncodeToString(sum[:])

			if *code.CodeChallenge != check {
				return oauth.Errorf(oauth.ErrorCodeInvalidClient, "code verifier mismatch")
			}
		}

		codeStore(ctx).AuthCodeDestroy(ctx, code.Code)

		user, prin, err := s.ctrl.UserGet(ctx, code.Subject)
		if err != nil {
			return oauth.Error(oauth.ErrorCodeInvalidClient, err)
		}

		oauth.AuthContext(ctx).User = user
		oauth.AuthContext(ctx).Principal = prin

		perms, ok := user.Permissions[code.Audience]
		if len(params.Scope) == 0 {
			if len(code.Scope) == 0 {
				code.Scope = perms
			}
			params.Scope = code.Scope
		}

		// check the scope against the code
		if !ok || !code.Scope.Every(params.Scope...) {
			return oauth.Errorf(oauth.ErrorCodeInvalidScope, "bad scope")
		}

		// ensure the app has access to this audience
		perms, ok = app.Permissions[aud.Name()]
		// check the scope against the app, audience and user permissions
		if !ok || !perms.Every(params.Scope...) {
			return oauth.Errorf(oauth.ErrorCodeInvalidScope, "unauthorized application scope")
		}

		// ensure the user has access to this audience
		perms, ok = user.Permissions[aud.Name()]
		if !ok || !perms.Every(params.Scope...) {
			return oauth.Errorf(oauth.ErrorCodeInvalidScope, "unauthorized user scope")
		}

		exp := time.Now().Add(time.Second * time.Duration(aud.TokenLifetime())).Unix()

		claims := oauth.Claims{
			"iss":   iss,
			"use":   "access",
			"iat":   time.Now().Unix(),
			"aud":   aud.Name(),
			"sub":   code.Subject,
			"scope": strings.Join(params.Scope, " "),
			"exp":   exp,
			"azp":   app.ClientID,
		}

		if code.Nonce != nil {
			claims["nonce"] = *code.Nonce
		}

		if roles, ok := user.Roles[aud.Name()]; ok {
			claims["roles"] = strings.Join(roles, " ")
		}

		token, err := s.ctrl.TokenFinalize(ctx, claims)
		if err != nil {
			return oauth.Error(oauth.ErrorCodeServerError, err)
		}

		bearer.AccessToken = token
		bearer.ExpiresIn = int64(exp - time.Now().Unix())
		scope := oauth.Permissions(params.Scope)

		// check for offline_access
		if scope.Contains(oauth.ScopeOffline) {
			refreshCode := *code

			if app.RefreshTokenLifetime > 0 {
				refreshCode.ExpiresAt = time.Now().Add(time.Hour * 24 * time.Duration(app.RefreshTokenLifetime)).Unix()
			} else {
				refreshCode.ExpiresAt = time.Now().Add(time.Hour * 24 * 7).Unix()
			}

			refreshCode.CodeChallenge = nil

			if params.RefreshNonce == nil {
				if params.ClientSecret == nil {
					return oauth.Errorf(oauth.ErrorCodeInvalidRequest, "missing refresh nonce")
				}
			} else {
				if refreshCode.RefreshNonce == *params.RefreshNonce {
					return oauth.Errorf(oauth.ErrorCodeInvalidGrant, "nonce reused")
				}
				refreshCode.RefreshNonce = *params.RefreshNonce
			}

			if err := codeStore(ctx).AuthCodeCreate(ctx, &refreshCode); err != nil {
				return oauth.Error(oauth.ErrorCodeServerError, err)
			}

			bearer.RefreshToken = refreshCode.Code
		}

		// check for id token request
		if scope.Contains(oauth.ScopeOpenID) {
			claims := oauth.Claims{
				"iss":       iss,
				"use":       "identity",
				"iat":       time.Now().Unix(),
				"auth_time": code.IssuedAt,
				"aud":       []string{aud.Name(), app.ClientID},
				"sub":       code.Subject,
				"exp":       time.Now().Add(time.Duration(app.TokenLifetime * int64(time.Second))).Unix(),
				"azp":       app.ClientID,
				"name":      user.Profile.Name,
			}

			if code != nil && code.Nonce != nil {
				claims["nonce"] = *code.Nonce
			}

			if scope.Contains(oauth.ScopeProfile) {
				dec, _ := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
					TagName: "json",
					Result:  &claims,
					Squash:  true,
				})

				if err := dec.Decode(user.Profile); err != nil {
					return oauth.Error(oauth.ErrorCodeServerError, err)
				}
			}

			token, err := s.ctrl.TokenFinalize(ctx, claims)
			if err != nil {
				return oauth.Error(oauth.ErrorCodeServerError, err)
			}
			bearer.IDToken = token
		}
	}

	return api.NewResponse(bearer)
}

func tokenIntrospect(ctx context.Context, params *TokenIntrospectParams) api.Responder {
	s := serverContext(ctx)

	if len(params.Token) == 22 {
		token, err := s.ctrl.TokenGet(ctx, params.Token)
		if err != nil {
			return api.Error(err)
		}

		if token.ExpiresAt().After(time.Now()) {
			token["active"] = true
		}

		return api.NewResponse(token)
	}

	t, err := s.ctrl.TokenValidate(ctx, params.Token)
	if err != nil {
		return api.Error(err)
	}

	if t.ExpiresAt().After(time.Now()) {
		t["active"] = true
	}

	return api.NewResponse(t)
}

func tokenRevoke(ctx context.Context, params *TokenRevokeParams) api.Responder {
	ctrl := oauth.AuthContext(ctx).Controller
	auth := oauth.AuthContext(ctx)

	if auth.User == nil {
		return oauth.Errorf(oauth.ErrorCodeInvalidClient, "missing user context")
	}

	if len(params.Token) == 22 {
		if err := ctrl.TokenRevoke(ctx, auth.User.Profile.Subject, params.Token); err != nil {
			return api.Error(err)
		}

		return api.NewResponse().WithStatus(http.StatusNoContent)
	}

	return oauth.Errorf(oauth.ErrorCodeInvalidRequest, "invalid token")
}
