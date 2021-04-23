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
	"net/http"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/oauth/pkg/oauth"
)

type (
	// LogoutParams contains all the bound params for the logout operation
	LogoutParams struct {
		Audience              *string `json:"audience,omitempty"`
		ClientID              *string `json:"client_id"`
		RedirectURI           *string `json:"redirect_uri,omitempty"`
		PostLogoutRedirectURI *string `json:"post_logout_redirect_uri,omitempty"`
		TokenHint             *string `json:"id_token_hint,omitempty"`
		State                 *string `json:"state"`
	}
)

func init() {
	registerRoutes([]route{
		{"/logout", http.MethodGet, &LogoutParams{}, logout, nil, nil},
	})
}

// Validate validates LogoutParams
func (p LogoutParams) Validate() error {
	return validation.Errors{
		"audience":                 validation.Validate(p.Audience, validation.NilOrNotEmpty),
		"client_id":                validation.Validate(p.ClientID, validation.When(p.TokenHint == nil, validation.Required).Else(validation.Nil)),
		"id_token_hint":            validation.Validate(p.TokenHint, validation.When(p.ClientID == nil, validation.Required).Else(validation.Nil)),
		"redirect_uri":             validation.Validate(p.RedirectURI, validation.NilOrNotEmpty, is.RequestURI),
		"post_logout_redirect_uri": validation.Validate(p.PostLogoutRedirectURI, validation.NilOrNotEmpty, is.RequestURI),
	}.Filter()
}

func logout(ctx context.Context, params *LogoutParams) api.Responder {
	ctrl := oauth.AuthContext(ctx).Controller
	log := api.Log(ctx)

	r, w := api.Request(ctx)

	if params.Audience == nil {
		aud := api.RequestHost(ctx)
		params.Audience = &aud
	}

	aud, err := ctrl.AudienceGet(ctx, *params.Audience)
	if err != nil {
		return oauth.Errorf(oauth.ErrorCodeInvalidRequest, "audience lookup failed: %s", err)
	}
	ctx = oauth.NewContext(ctx, aud)

	if params.TokenHint != nil {
		claims, err := ctrl.TokenValidate(ctx, *params.TokenHint)
		if err != nil {
			return oauth.Error(oauth.ErrorCodeInvalidClient, err)
		}
		clientID := claims.ClientID()

		params.ClientID = &clientID
	}

	// ensure this is a valid application
	app, err := ctrl.ApplicationGet(ctx, *params.ClientID)
	if err != nil {
		return oauth.Errorf(oauth.ErrorCodeInvalidClient, "application lookup failed: %s", err)
	}

	ctx = oauth.NewContext(ctx, app)

	// openid connect parameter has precedence
	if params.PostLogoutRedirectURI != nil {
		params.RedirectURI = params.PostLogoutRedirectURI
	}

	if (params.RedirectURI == nil || *params.RedirectURI == "") && len(app.RedirectUris[aud.Name()]) > 0 {
		params.RedirectURI = &app.RedirectUris[aud.Name()][0]
	}

	u, err := EnsureURI(*params.RedirectURI, app.RedirectUris[aud.Name()], r)
	if err != nil {
		return oauth.Error(oauth.ErrorCodeAccessDenied, err)
	}

	if err := sessionStore(ctx).SessionDestroy(ctx, w, r); err != nil && !errors.Is(err, oauth.ErrSessionNotFound) {
		log.Error(err.Error())

		api.Redirect(u, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})

	}

	q := u.Query()

	if params.State != nil {
		q.Set("state", *params.State)
	}

	u.RawQuery = q.Encode()

	return api.Redirect(u)
}
