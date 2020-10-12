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
	"net/http"
	"net/url"
	"time"

	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/oauth/api/server/auth"
	"github.com/libatomic/oauth/pkg/oauth"
)

func init() {
	registerRoutes([]route{
		{"/login", http.MethodPost, &auth.LoginParams{}, login, nil},
	})
}

func login(ctx context.Context, params *auth.LoginParams) api.Responder {
	ctrl := getController(ctx)

	pubKey, err := ctrl.TokenPublicKey(ctx)
	if err != nil {
		return api.Error(err)
	}

	req := &oauth.AuthRequest{}
	if err := verifyValue(ctx, pubKey, AuthRequestParam, params.RequestToken, req); err != nil {
		return api.Error(err).WithStatus(http.StatusBadRequest)
	}

	if time.Unix(req.ExpiresAt, 0).Before(time.Now()) {
		return api.Errorf("expired request token").WithStatus(http.StatusUnauthorized)
	}

	u, _ := url.Parse(req.RedirectURI)

	ctx, err = oauth.ContextFromRequest(ctx, ctrl, req)
	if err != nil {
		return api.Error(err)
	}

	user, _, err := ctrl.UserAuthenticate(ctx, params.Login, params.Password)
	if err != nil {
		return api.Error(err).WithStatus(http.StatusUnauthorized)
	}

	oauth.GetContext(ctx).User = user

	perms, ok := user.Permissions[req.Audience]
	if !ok {
		return api.Errorf("user authorization failed").WithStatus(http.StatusUnauthorized)
	}

	if len(req.Scope) == 0 {
		req.Scope = perms
	}

	if !perms.Every(req.Scope...) {
		return api.Errorf("user authorization failed").WithStatus(http.StatusUnauthorized)
	}

	w, r := params.UnbindRequest()

	session, err := ctrl.SessionCreate(ctx, r)
	if err != nil {
		return api.Error(err)
	}

	if err := session.Write(w); err != nil {
		return api.Error(err)
	}

	authCode := &oauth.AuthCode{
		AuthRequest:       *req,
		Subject:           user.Profile.Subject,
		SessionID:         session.ID(),
		UserAuthenticated: true,
	}
	if err := ctrl.AuthCodeCreate(ctx, authCode); err != nil {
		return api.Error(err)
	}

	u, _ = url.Parse(req.RedirectURI)

	q := u.Query()

	q.Set("code", authCode.Code)

	if req.State != nil {
		q.Set("state", *req.State)
	}

	u.RawQuery = q.Encode()

	return api.Redirect(u)
}
