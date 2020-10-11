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
	"time"

	"github.com/go-openapi/runtime"
	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/oauth/api/server/auth"
	"github.com/libatomic/oauth/pkg/oauth"
)

func init() {
	registerRoutes([]route{
		{"/signup", http.MethodPost, &auth.SignupParams{}, signup, nil},
	})
}

func signup(ctx context.Context, params *auth.SignupParams) api.Responder {
	var err error

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
		return api.StatusErrorf(http.StatusUnauthorized, "expired request token")
	}

	octx, err := oauth.ContextFromRequest(ctx, ctrl, req)
	if err != nil {
		return api.StatusError(http.StatusInternalServerError, err)
	}

	if _, err := ctrl.UserCreate(octx, oauth.User{
		Login: params.Login,
		Profile: oauth.Profile{
			Name:  safestr(params.Name),
			Email: params.Email,
		},
	}, params.Password, safestr(params.InviteCode)); err != nil {
		return api.StatusError(http.StatusBadRequest, err)
	}

	rw, r := params.UnbindRequest()

	loginParams := &auth.LoginParams{
		Login: params.Login,

		Password: params.Password,

		RequestToken: params.RequestToken,
	}

	loginParams.BindRequest(rw, r, runtime.DiscardConsumer)

	return login(ctx, loginParams)
}
