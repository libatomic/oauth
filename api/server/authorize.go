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
	"time"

	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/oauth/api/server/auth"
	"github.com/libatomic/oauth/pkg/oauth"
)

func init() {
	registerRoutes([]route{
		{"/authorize", http.MethodGet, &auth.AuthorizeParams{}, authorize, nil},
	})
}

func authorize(ctx context.Context, params *auth.AuthorizeParams) api.Responder {
	ctrl := getController(ctx)
	log := api.Log(ctx)

	// ensure this is a valid application
	app, err := ctrl.ApplicationGet(ctx, params.ClientID)
	if err != nil {
		return api.Error(err).WithStatus(http.StatusBadRequest)
	}

	// enusure this app supports the authorization_code flow
	if !app.AllowedGrants.Contains("authorization_code") {
		return api.Errorf("authorization_code grant not permitted").WithStatus(http.StatusUnauthorized)
	}

	if params.RedirectURI == nil && len(app.RedirectUris) > 0 {
		params.RedirectURI = &app.RedirectUris[0]
	}

	// ensure the redirect uri path is allowed
	u, err := ensureURI(*params.RedirectURI, app.RedirectUris)
	if err != nil {
		return api.Errorf("unauthorized redirect uri").WithStatus(http.StatusUnauthorized)
	}

	if params.AppURI == nil && len(app.AppUris) > 0 {
		params.AppURI = &app.AppUris[0]
	}

	appURI, err := ensureURI(*params.AppURI, app.AppUris)
	if err != nil {
		return api.Redirect(u, map[string]string{
			"error":             "access_denied",
			"error_description": err.Error(),
		})
	}

	// ensure the audience
	aud, err := ctrl.AudienceGet(ctx, params.Audience)
	if err != nil {
		log.Error(err.Error())

		return api.Redirect(u, map[string]string{
			"error":             "bad_request",
			"error_description": "invalid audience",
		})
	}

	if len(params.Scope) > 0 && len(app.Permissions) > 0 {
		// check the scope against the app and audience
		perms, ok := app.Permissions[params.Audience]
		if !ok || !perms.Every(params.Scope...) {
			return api.Redirect(u, map[string]string{
				"error":             "access_denied",
				"error_description": "invalid audience",
			})
		}

		// sanity check to ensure the audience actually has the permissions requested
		if !aud.Permissions.Every(params.Scope...) {
			return api.Redirect(u, map[string]string{
				"error":             "access_denied",
				"error_description": "insufficient permissions",
			})
		}
	}

	req := &oauth.AuthRequest{
		ClientID:            params.ClientID,
		RedirectURI:         *params.RedirectURI,
		Scope:               params.Scope,
		Audience:            params.Audience,
		UserPool:            params.UserPool,
		State:               params.State,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: *params.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(time.Minute * 10).Unix(),
	}

	w, r := params.UnbindRequest()

	session, err := ctrl.SessionRead(r)
	if err != nil && !errors.Is(err, oauth.ErrSessionNotFound) {
		return api.Redirect(u, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})
	}

	// if we already have a session, use that to create the code
	if session != nil {
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
		if err := ctrl.AuthCodeCreate(oauth.NewContext(
			ctx,
			oauth.WithApplication(app),
			oauth.WithAudience(aud),
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

	privKey, err := ctrl.TokenPrivateKey(oauth.NewContext(
		ctx,
		oauth.WithApplication(app),
		oauth.WithAudience(aud),
	))
	if err != nil {
		return api.Redirect(u, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})
	}

	token, err := signValue(ctx, privKey, AuthRequestParam, req)
	if err != nil {
		return api.Redirect(u, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})
	}

	q := appURI.Query()

	q.Set(AuthRequestParam, token)

	appURI.RawQuery = q.Encode()

	return api.Redirect(appURI)
}
