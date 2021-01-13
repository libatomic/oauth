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
		Audience    *string `json:"audience,omitempty"`
		ClientID    string  `json:"client_id"`
		RedirectURI *string `json:"redirect_uri"`
		State       *string `json:"state"`
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
		"audience":     validation.Validate(p.Audience, validation.NilOrNotEmpty),
		"client_id":    validation.Validate(p.ClientID, validation.Required),
		"redirect_uri": validation.Validate(p.RedirectURI, validation.NilOrNotEmpty, is.RequestURI),
	}.Filter()
}

func logout(ctx context.Context, params *LogoutParams) api.Responder {
	ctrl := oauthController(ctx)
	log := api.Log(ctx)

	r, w := api.Request(ctx)

	if params.Audience == nil {
		aud := r.URL.Hostname()
		params.Audience = &aud
	}

	aud, err := ctrl.AudienceGet(ctx, *params.Audience)
	if err != nil {
		return api.StatusError(http.StatusBadRequest, err)
	}
	ctx = oauth.NewContext(ctx, aud)

	// ensure this is a valid application
	app, err := ctrl.ApplicationGet(ctx, params.ClientID)
	if err != nil {
		return api.StatusError(http.StatusBadRequest, err)
	}

	ctx = oauth.NewContext(ctx, oauth.Context{
		Application: app,
		Audience:    aud,
	})

	if (params.RedirectURI == nil || *params.RedirectURI == "") && len(app.RedirectUris[aud.Name()]) > 0 {
		params.RedirectURI = &app.RedirectUris[aud.Name()][0]
	}

	u, err := EnsureURI(*params.RedirectURI, app.RedirectUris[aud.Name()])
	if err != nil {
		return api.Error(err).WithStatus(http.StatusBadRequest)
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
