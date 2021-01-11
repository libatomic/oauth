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
	"path"
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
		ClientID        string   `json:"client_id"`
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
)

func init() {
	registerRoutes([]route{
		{"/token", http.MethodPost, &TokenParams{}, token, nil},
	})
}

// Validate validate TokenParams
func (p TokenParams) Validate() error {
	return validation.Errors{
		"audience":         validation.Validate(p.Audience, validation.NilOrNotEmpty),
		"client_id":        validation.Validate(p.ClientID, validation.Required),
		"client_secret":    validation.Validate(p.ClientSecret, validation.NilOrNotEmpty),
		"code":             validation.Validate(p.Code, validation.NilOrNotEmpty),
		"code_verifier":    validation.Validate(p.CodeVerifier, validation.NilOrNotEmpty),
		"grant_Type":       validation.Validate(p.GrantType, validation.Required),
		"password":         validation.Validate(p.Password, validation.NilOrNotEmpty),
		"refresh_nonce":    validation.Validate(p.RefreshNonce, validation.NilOrNotEmpty),
		"refresh_token":    validation.Validate(p.RefreshToken, validation.NilOrNotEmpty),
		"refresh_verifier": validation.Validate(p.RefreshVerifier, validation.NilOrNotEmpty),
		"scope":            validation.Validate(p.Scope, validation.NilOrNotEmpty),
		"username":         validation.Validate(p.Username, validation.NilOrNotEmpty),
	}.Filter()
}

func token(ctx context.Context, params *TokenParams) api.Responder {
	s := serverContext(ctx)

	r, _ := api.Request(ctx)

	if params.Audience == nil {
		aud := r.URL.Hostname()
		params.Audience = &aud
	}

	// ensure the audience
	aud, err := s.ctrl.AudienceGet(ctx, *params.Audience)
	if err != nil {
		return api.StatusError(http.StatusBadRequest, err)
	}
	ctx = oauth.NewContext(ctx, aud)

	// ensure this is a valid application
	app, err := s.ctrl.ApplicationGet(ctx, params.ClientID)
	if err != nil {
		return api.StatusError(http.StatusBadRequest, err)
	}
	ctx = oauth.NewContext(ctx, app)

	bearer := &oauth.BearerToken{
		TokenType: "bearer",
	}

	if g, ok := app.AllowedGrants[aud.Name()]; !ok || !g.Contains(params.GrantType) {
		return api.StatusErrorf(http.StatusUnauthorized, "unauthorized grant")
	}

	// ensure the controller allows these grants
	if !s.allowedGrants.Contains(params.GrantType) {
		return api.StatusErrorf(http.StatusUnauthorized, "invalid grant type")
	}

	// sanity check to ensure the audience actually has the permissions requested
	if !aud.Permissions().Every(params.Scope...) {
		return api.StatusErrorf(http.StatusUnauthorized, "bad scope")
	}

	issuer := fmt.Sprintf("https://%s%s", r.Host, path.Clean(path.Join(path.Dir(r.URL.Path), "/.well-known/jwks.json")))

	var code *oauth.AuthCode
	var user *oauth.User

	switch params.GrantType {
	case oauth.GrantTypePassword:
		if params.ClientID != app.ClientID {
			return api.StatusErrorf(http.StatusBadRequest, "bad client id")
		}
		if params.ClientSecret == nil || *params.ClientSecret != app.ClientSecret {
			return api.StatusErrorf(http.StatusBadRequest, "bad client secret")
		}

		if params.Username == nil || params.Password == nil {
			return api.StatusErrorf(http.StatusBadRequest, "bad credentials")
		}

		user, _, err = s.ctrl.UserAuthenticate(
			ctx,
			*params.Username,
			*params.Password,
		)
		if err != nil {
			return api.StatusErrorf(http.StatusUnauthorized, "not authorized")
		}

		if len(params.Scope) == 0 {
			params.Scope = user.Permissions[*params.Audience]
		}
		fallthrough

	case oauth.GrantTypeClientCredentials:
		if params.ClientSecret == nil || *params.ClientSecret != app.ClientSecret {
			return api.StatusErrorf(http.StatusBadRequest, "bad client secret")
		}

		// ensure this app has these permissions
		perms, ok := app.Permissions[*params.Audience]
		if !ok || !perms.Every(params.Scope...) {
			return api.StatusErrorf(http.StatusUnauthorized, "bad scope")
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
		claims["iss"] = issuer
		claims["azp"] = app.ClientID

		token, err := s.ctrl.TokenFinalize(ctx, claims)
		if err != nil {
			return api.StatusError(http.StatusInternalServerError, err)
		}
		bearer.AccessToken = token
		bearer.ExpiresIn = int64(exp - time.Now().Unix())

	case oauth.GrantTypeRefreshToken:
		if params.RefreshToken == nil || params.RefreshVerifier == nil {
			return api.StatusErrorf(http.StatusBadRequest, "missing refresh token or verifier")
		}

		code, err = codeStore(ctx).AuthCodeGet(ctx, *params.RefreshToken)
		if err != nil {
			return api.StatusErrorf(http.StatusUnauthorized, "invalid refresh token")
		}

		sum := sha256.Sum256([]byte(*params.RefreshVerifier))
		check := base64.RawURLEncoding.EncodeToString(sum[:])

		if code.RefreshNonce != check {
			return api.StatusErrorf(http.StatusUnauthorized, "token validation failed")
		}

		fallthrough

	case oauth.GrantTypeAuthCode:
		if code == nil {
			if params.Code == nil || params.CodeVerifier == nil {
				return api.StatusErrorf(http.StatusBadRequest, "missing code or verifier")
			}

			code, err = codeStore(ctx).AuthCodeGet(ctx, *params.Code)
			if err != nil {
				return api.StatusErrorf(http.StatusUnauthorized, "invalid code")
			}

			oauth.AuthContext(ctx).Request = &code.AuthRequest

			sum := sha256.Sum256([]byte(*params.CodeVerifier))
			check := base64.RawURLEncoding.EncodeToString(sum[:])

			if code.CodeChallenge != check {
				return api.Errorf("verifier mismatch").WithStatus(http.StatusUnauthorized)
			}
		}

		codeStore(ctx).AuthCodeDestroy(ctx, code.Code)

		user, prin, err := s.ctrl.UserGet(ctx, code.Subject)
		if err != nil {
			return api.StatusErrorf(http.StatusUnauthorized, err.Error())
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
			return api.StatusErrorf(http.StatusUnauthorized, "invalid request scope")
		}

		// ensure the app has access to this audience
		perms, ok = app.Permissions[aud.Name()]
		// check the scope against the app, audience and user permissions
		if !ok || !perms.Every(params.Scope...) {
			return api.StatusErrorf(http.StatusUnauthorized, "invalid application scope")
		}

		// ensure the user has access to this audience
		perms, ok = user.Permissions[aud.Name()]
		if !ok || !perms.Every(params.Scope...) {
			return api.StatusErrorf(http.StatusUnauthorized, "invalid user scope")
		}

		exp := time.Now().Add(time.Second * time.Duration(aud.TokenLifetime())).Unix()

		claims := oauth.Claims{
			"iss":   issuer,
			"use":   "access",
			"iat":   time.Now().Unix(),
			"aud":   aud.Name,
			"sub":   code.Subject,
			"scope": strings.Join(params.Scope, " "),
			"exp":   exp,
			"azp":   app.ClientID,
		}

		if roles, ok := user.Roles[aud.Name()]; ok {
			claims["roles"] = strings.Join(roles, " ")
		}

		token, err := s.ctrl.TokenFinalize(ctx, claims)
		if err != nil {
			return api.StatusError(http.StatusInternalServerError, err)
		}

		bearer.AccessToken = token
		bearer.ExpiresIn = int64(exp - time.Now().Unix())
		scope := oauth.Permissions(params.Scope)

		// check for offline_access
		if scope.Contains(oauth.ScopeOffline) {
			if params.RefreshNonce == nil {
				return api.StatusErrorf(http.StatusUnauthorized, "missing refresh nonce")
			}

			if code.RefreshNonce == *params.RefreshNonce {
				return api.StatusErrorf(http.StatusUnauthorized, "nonce reused")
			}
			code.RefreshNonce = *params.RefreshNonce

			if err := codeStore(ctx).AuthCodeCreate(ctx, code); err != nil {
				return api.StatusError(http.StatusInternalServerError, err)
			}

			bearer.RefreshToken = code.Code
		}

		// check for id token request
		if scope.Contains(oauth.ScopeOpenID) {
			claims := oauth.Claims{
				"iss":       issuer,
				"use":       "identity",
				"iat":       time.Now().Unix(),
				"auth_time": code.IssuedAt,
				"aud":       aud.Name,
				"sub":       code.Subject,
				"exp":       time.Now().Add(time.Duration(app.TokenLifetime)).Unix(),
				"azp":       app.ClientID,
				"name":      user.Profile.Name,
			}

			if scope.Contains(oauth.ScopeProfile) {
				dec, _ := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
					TagName: "json",
					Result:  &claims,
				})

				if err := dec.Decode(user.Profile); err != nil {
					return api.StatusError(http.StatusInternalServerError, err)
				}
			}

			token, err := s.ctrl.TokenFinalize(ctx, claims)
			if err != nil {
				return api.StatusError(http.StatusInternalServerError, err)
			}
			bearer.IDToken = token
		}
	}

	return api.NewResponse(bearer)
}
