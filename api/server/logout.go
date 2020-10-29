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
	"errors"
	"net/http"

	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/oauth/api/server/auth"
	"github.com/libatomic/oauth/pkg/oauth"
)

func init() {
	registerRoutes([]route{
		{"/logout", http.MethodGet, &auth.LogoutParams{}, logout, nil},
	})
}

func logout(ctx context.Context, params *auth.LogoutParams) api.Responder {
	ctrl := getController(ctx)
	log := api.Log(ctx)

	aud, err := ctrl.AudienceGet(ctx, params.Audience)
	if err != nil {
		return api.StatusError(http.StatusBadRequest, err)
	}
	ctx = oauth.NewContext(ctx, aud)

	// ensure this is a valid application
	app, err := ctrl.ApplicationGet(ctx, params.ClientID)
	if err != nil {
		return api.StatusError(http.StatusBadRequest, err)
	}

	aud, err := ctrl.AudienceGet(ctx, params.Audience)
	if err != nil {
		return api.StatusError(http.StatusBadRequest, err)
	}

	ctx = oauth.NewContext(ctx, oauth.Context{
		Application: app,
		Audience:    aud,
	})

	if (params.RedirectURI == nil || *params.RedirectURI == "") && len(app.RedirectUris) > 0 {
		params.RedirectURI = &app.RedirectUris[0]
	}

	u, err := ensureURI(*params.RedirectURI, app.RedirectUris)
	if err != nil {
		return api.Error(err).WithStatus(http.StatusBadRequest)
	}

	w, r := params.UnbindRequest()
	if err := ctrl.SessionDestroy(ctx, w, r); err != nil && !errors.Is(err, oauth.ErrSessionNotFound) {
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
