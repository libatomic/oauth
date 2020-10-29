/*
 * Copyright (C) 2020 Atomic Media Foundation
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file in the root of this
 * workspace for details.
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

	"github.com/dgrijalva/jwt-go"
	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/oauth/api/server/auth"
	"github.com/libatomic/oauth/pkg/oauth"
	"github.com/mitchellh/mapstructure"
)

func init() {
	registerRoutes([]route{
		{"/token", http.MethodPost, &auth.TokenParams{}, token, nil},
	})
}

func token(ctx context.Context, params *auth.TokenParams) api.Responder {
	ctrl := getController(ctx)

	// ensure the audience
	aud, err := ctrl.AudienceGet(params.Context(), params.Audience)
	if err != nil {
		return api.StatusError(http.StatusBadRequest, err)
	}
	ctx = oauth.NewContext(ctx, aud)

	// ensure this is a valid application
	app, err := ctrl.ApplicationGet(ctx, params.ClientID)
	if err != nil {
		return api.StatusError(http.StatusBadRequest, err)
	}
	ctx = oauth.NewContext(ctx, app)

	bearer := &oauth.BearerToken{
		TokenType: "bearer",
	}

	if !app.AllowedGrants.Contains(params.GrantType) {
		return api.StatusErrorf(http.StatusUnauthorized, "unauthorized grant")
	}

	// ensure the controller allows these grants
	if !ctrl.AuthorizedGrantTypes(ctx).Contains(params.GrantType) {
		return api.StatusErrorf(http.StatusUnauthorized, "invalid grant type")
	}

	// sanity check to ensure the audience actually has the permissions requested
	if !aud.Permissions.Every(params.Scope...) {
		return api.StatusErrorf(http.StatusUnauthorized, "bad scope")
	}

	_, r := params.UnbindRequest()

	signToken := func(ctx context.Context, claims jwt.MapClaims) (string, error) {
		var token *jwt.Token
		var key interface{}

		claims["iss"] = fmt.Sprintf("https://%s%s", r.Host, path.Clean(path.Join(path.Dir(r.URL.Path), "/.well-known/jwks.json")))

		switch aud.TokenAlgorithm {
		case "RS256":
			signingKey, err := ctrl.TokenPrivateKey(ctx)
			if err != nil {
				return "", err
			}

			token = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			key = signingKey

		case "HS256":
			token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
			key = []byte(aud.TokenSecret)
		}
		return token.SignedString(key)
	}

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

		user, _, err = ctrl.UserAuthenticate(
			ctx,
			*params.Username,
			*params.Password,
		)
		if err != nil {
			return api.StatusErrorf(http.StatusUnauthorized, "not authorized")
		}

		if len(params.Scope) == 0 {
			params.Scope = user.Permissions[params.Audience]
		}
		fallthrough

	case oauth.GrantTypeClientCredentials:
		if params.ClientSecret == nil || *params.ClientSecret != app.ClientSecret {
			return api.StatusErrorf(http.StatusBadRequest, "bad client secret")
		}

		// ensure this app has these permissions
		perms, ok := app.Permissions[params.Audience]
		if !ok || !perms.Every(params.Scope...) {
			return api.StatusErrorf(http.StatusUnauthorized, "bad scope")
		}

		claims := make(jwt.MapClaims)

		exp := time.Now().Add(time.Second * time.Duration(aud.TokenLifetime)).Unix()

		if user != nil {
			claims["sub"] = user.Profile.Subject
		} else {
			claims["sub"] = fmt.Sprintf("%s@applications", app.ClientID)
		}
		claims["aud"] = aud.Name
		claims["exp"] = exp
		claims["iat"] = time.Now().Unix()
		claims["scope"] = strings.Join(params.Scope, " ")

		ctrl.TokenFinalize(
			ctx,
			params.Scope,
			claims,
		)

		token, err := signToken(ctx, claims)
		if err != nil {
			return api.StatusError(http.StatusInternalServerError, err)

		}
		bearer.AccessToken = token
		bearer.ExpiresIn = int64(exp - time.Now().Unix())

	case oauth.GrantTypeRefreshToken:
		if params.RefreshToken == nil || params.RefreshVerifier == nil {
			return api.StatusErrorf(http.StatusBadRequest, "missing refresh token or verifier")
		}

		code, err = ctrl.AuthCodeGet(ctx, *params.RefreshToken)
		if err != nil {
			return api.StatusErrorf(http.StatusUnauthorized, "invalid refresh token")
		}

		verifier, err := base64.RawURLEncoding.DecodeString(*params.RefreshVerifier)
		if err != nil {
			return api.StatusError(http.StatusBadRequest, err)
		}

		sum := sha256.Sum256(verifier)
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

			code, err = ctrl.AuthCodeGet(ctx, *params.Code)
			if err != nil {
				return api.StatusErrorf(http.StatusUnauthorized, "invalid code")
			}

			oauth.GetContext(ctx).Request = &code.AuthRequest

			verifier, err := base64.RawURLEncoding.DecodeString(*params.CodeVerifier)
			if err != nil {
				return api.StatusError(http.StatusBadRequest, err)
			}

			sum := sha256.Sum256(verifier)
			check := base64.RawURLEncoding.EncodeToString(sum[:])

			if code.CodeChallenge != check {
				return api.Errorf("verifier mismatch").WithStatus(http.StatusUnauthorized)
			}
		}

		ctrl.AuthCodeDestroy(ctx, code.Code)

		user, prin, err := ctrl.UserGet(ctx, code.Subject)
		if err != nil {
			return api.StatusErrorf(http.StatusUnauthorized, err.Error())
		}

		oauth.GetContext(ctx).User = user
		oauth.GetContext(ctx).Principal = prin

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
		perms, ok = app.Permissions[aud.Name]
		// check the scope against the app, audience and user permissions
		if !ok || !perms.Every(params.Scope...) {
			return api.StatusErrorf(http.StatusUnauthorized, "invalid application scope")
		}

		// ensure the user has access to this audience
		perms, ok = user.Permissions[aud.Name]
		if !ok || !perms.Every(params.Scope...) {
			return api.StatusErrorf(http.StatusUnauthorized, "invalid user scope")
		}

		exp := time.Now().Add(time.Second * time.Duration(aud.TokenLifetime)).Unix()

		claims := jwt.MapClaims{
			"iat":   time.Now().Unix(),
			"aud":   aud.Name,
			"sub":   code.Subject,
			"scope": strings.Join(params.Scope, " "),
			"exp":   exp,
			"azp":   app.ClientID,
		}

		ctrl.TokenFinalize(
			ctx,
			params.Scope,
			claims,
		)

		token, err := signToken(ctx, claims)
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

			if err := ctrl.AuthCodeCreate(ctx, code); err != nil {
				return api.StatusError(http.StatusInternalServerError, err)
			}

			bearer.RefreshToken = code.Code
		}

		// check for id token request
		if scope.Contains(oauth.ScopeOpenID) {
			claims := jwt.MapClaims{
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

			token, err := signToken(ctx, claims)
			if err != nil {
				return api.StatusError(http.StatusInternalServerError, err)
			}
			bearer.IDToken = token
		}
	}

	return api.NewResponse(bearer)
}
