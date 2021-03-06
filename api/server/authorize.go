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
	"errors"
	"fmt"
	"net/http"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/oauth/pkg/oauth"
)

type (
	// AuthorizeParams contains all the bound params for the authorize operation
	AuthorizeParams struct {
		AppURI              *string  `json:"app_uri"`
		Audience            *string  `json:"audience,omitempty"`
		ClientID            string   `json:"client_id"`
		CodeChallenge       *string  `json:"code_challenge"`
		CodeChallengeMethod *string  `json:"code_challenge_method,omitempty"`
		RedirectURI         *string  `json:"redirect_uri"`
		ResponseType        string   `json:"response_type"`
		Scope               []string `json:"scope"`
		State               *string  `json:"state,omitempty"`
		Nonce               *string  `json:"nonce,omitempty"`
	}
)

var (
	// DefaultCodeChallengeMethod is the only challenge method
	DefaultCodeChallengeMethod = "plain"
)

func init() {
	registerRoutes([]route{
		{"/authorize", http.MethodGet, &AuthorizeParams{}, authorize, nil, nil},
	})
}

// Validate validates the params
func (p *AuthorizeParams) Validate() error {
	if err := (validation.Errors{
		"app_uri":               validation.Validate(p.AppURI, validation.NilOrNotEmpty, is.RequestURI),
		"audience":              validation.Validate(p.Audience, validation.NilOrNotEmpty),
		"client_id":             validation.Validate(p.ClientID, validation.Required),
		"code_challenge":        validation.Validate(p.CodeChallenge, validation.NilOrNotEmpty),
		"code_challenge_method": validation.Validate(p.CodeChallengeMethod, validation.NilOrNotEmpty, validation.In("plain", "S256")),
		"redirect_uri":          validation.Validate(p.RedirectURI, validation.NilOrNotEmpty, is.RequestURI),
		"response_type":         validation.Validate(p.ResponseType, validation.Required),
		"scope":                 validation.Validate(p.Scope, validation.NilOrNotEmpty),
	}).Filter(); err != nil {
		return err
	}

	if p.CodeChallengeMethod == nil {
		p.CodeChallengeMethod = &DefaultCodeChallengeMethod
	}

	return nil
}

func authorize(ctx context.Context, params *AuthorizeParams) api.Responder {
	s := serverContext(ctx)
	ctrl := oauth.AuthContext(ctx).Controller
	log := api.Log(ctx)

	r, w := api.Request(ctx)

	if params.Audience == nil {
		aud := api.RequestHost(ctx)
		params.Audience = &aud
	}

	// ensure the audience
	aud, err := ctrl.AudienceGet(ctx, *params.Audience)
	if err != nil {
		return oauth.Errorf(oauth.ErrorCodeInvalidRequest, "audience lookup failed: %s", err)
	}

	ctx = oauth.NewContext(ctx, aud)

	// ensure this is a valid application
	app, err := ctrl.ApplicationGet(ctx, params.ClientID)
	if err != nil {
		return oauth.Errorf(oauth.ErrorCodeInvalidClient, "application lookup failed: %s", err)
	}

	ctx = oauth.NewContext(ctx, app)

	if len(app.RedirectUris) == 0 || len(app.RedirectUris[aud.Name()]) == 0 {
		return oauth.Errorf(oauth.ErrorCodeInvalidRequest, "application has no valid redirect uri")
	}

	if params.RedirectURI == nil && len(app.RedirectUris[aud.Name()]) > 0 {
		params.RedirectURI = &app.RedirectUris[aud.Name()][0]
	}

	// ensure the redirect uri path is allowed
	u, err := EnsureURI(*params.RedirectURI, app.RedirectUris[aud.Name()], r)
	if err != nil {
		return oauth.Errorf(oauth.ErrorCodeAccessDenied, "unauthorized redirect uri")
	}

	// enusure this app supports the authorization_code flow
	if g, ok := app.AllowedGrants[aud.Name()]; !ok || !g.Contains("authorization_code") {
		return api.Redirect(u, map[string]string{
			"error":             "access_denied",
			"error_description": "unsupported grant",
		})
	}

	if len(app.AppUris) == 0 || len(app.AppUris[aud.Name()]) == 0 {
		return api.Redirect(u, map[string]string{
			"error":             "access_denied",
			"error_description": "application has no valid app uris",
		})
	}

	if params.AppURI == nil && len(app.AppUris[aud.Name()]) > 0 {
		params.AppURI = &app.AppUris[aud.Name()][0]
	}

	appURI, err := EnsureURI(*params.AppURI, app.AppUris[aud.Name()], r)
	if err != nil {
		return api.Redirect(u, map[string]string{
			"error":             "access_denied",
			"error_description": fmt.Sprintf("%s: app_uri", err),
		})
	}

	if len(params.Scope) > 0 && len(app.Permissions) > 0 {
		// sanity check to ensure the audience actually has the permissions requested
		if !aud.Permissions().Every(params.Scope...) {
			return api.Redirect(u, map[string]string{
				"error":             "access_denied",
				"error_description": "insufficient audience permissions",
			})
		}

		// check the scope against the app and audience
		perms, ok := app.Permissions[aud.Name()]
		if !ok || !perms.Every(params.Scope...) {
			return api.Redirect(u, map[string]string{
				"error":             "access_denied",
				"error_description": "invalid application scope",
			})
		}
	}

	req := &oauth.AuthRequest{
		ClientID:            params.ClientID,
		AppURI:              *params.AppURI,
		RedirectURI:         *params.RedirectURI,
		Scope:               params.Scope,
		Audience:            aud.Name(),
		State:               params.State,
		Nonce:               params.Nonce,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: *params.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(s.requestTokenLifetime).Unix(),
	}

	session, err := sessionStore(ctx).SessionRead(ctx, r)
	if err != nil && !errors.Is(err, oauth.ErrSessionNotFound) {
		return api.Redirect(u, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})
	}

	// if we already have a session, use that to create the code
	if session != nil {
		scope := session.Scope(aud.Name())
		if scope.Empty() || scope.Every(params.Scope...) {
			_, _, err := ctrl.UserGet(ctx, session.Subject())
			if err != nil {
				sessionStore(ctx).SessionDestroy(ctx, w, r)

				return api.Redirect(u, map[string]string{
					"error":             "access_denied",
					"error_description": "user not found",
				})
			}

			session.Set(fmt.Sprintf("scope:%s", aud.Name()), params.Scope)

			if err := session.Write(w); err != nil {
				return api.Redirect(u, map[string]string{
					"error":             "server_error",
					"error_description": err.Error(),
				})
			}

			authCode := &oauth.AuthCode{
				AuthRequest: *req,
				Subject:     session.Subject(),
				SessionID:   session.ID(),
			}
			if err := codeStore(ctx).AuthCodeCreate(oauth.NewContext(
				ctx,
				oauth.Context{
					Application: app,
					Audience:    aud,
				},
			), authCode); err != nil {
				log.Error(err.Error())

				return api.Redirect(u, map[string]string{
					"error":             "server_error",
					"error_description": err.Error(),
				})
			}

			q := u.Query()

			q.Set("code", authCode.Code)

			if req.State != nil {
				q.Set("state", *req.State)
			}

			u.RawQuery = q.Encode()

			return api.Redirect(u)
		}
	}

	token, err := signValue(ctx, ctrl.TokenFinalize, req)
	if err != nil {
		return api.Redirect(u, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})
	}

	q := appURI.Query()

	q.Set(AuthRequestParam, token)
	q.Set("mode", "password")

	appURI.RawQuery = q.Encode()

	return api.Redirect(appURI)
}
