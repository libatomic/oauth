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

	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/oauth/api/server/user"
	"github.com/libatomic/oauth/pkg/oauth"
)

func init() {
	registerRoutes([]route{
		{"/userInfo", http.MethodPut, &user.UserInfoUpdateParams{}, userInfoUpdate, oauth.Scope(oauth.ScopeOpenID, oauth.ScopeProfile)},
		{"/userInfo", http.MethodGet, &user.UserInfoGetParams{}, userInfo, oauth.Scope(oauth.ScopeOpenID, oauth.ScopeProfile)},
		{"/userPrincipal", http.MethodGet, &user.UserPrincipalGetParams{}, userPrincipal, oauth.Scope(oauth.ScopeOpenID, oauth.ScopeProfile)},
	})
}

func userInfoUpdate(ctx context.Context, params *user.UserInfoUpdateParams) api.Responder {
	ctrl := getController(ctx)
	auth := api.Principal(ctx).(oauth.Context)

	if auth.User() == nil {
		return api.StatusErrorf(http.StatusUnauthorized, "invalid token")
	}

	user := auth.User()
	user.Profile = params.Profile

	if err := ctrl.UserUpdate(auth, user); err != nil {
		return api.Error(err)
	}

	return api.NewResponse(user.Profile)
}

func userInfo(ctx context.Context, params *user.UserInfoGetParams) api.Responder {
	auth := api.Principal(ctx).(oauth.Context)

	if auth.User() == nil {
		return api.StatusErrorf(http.StatusUnauthorized, "invalid token")
	}

	return api.NewResponse(auth.User().Profile)
}

func userPrincipal(ctx context.Context, params *user.UserPrincipalGetParams) api.Responder {
	auth := api.Principal(ctx).(oauth.Context)

	if auth.Principal() == nil {
		return api.StatusErrorf(http.StatusUnauthorized, "invalid token")
	}

	return api.NewResponse(auth.Principal())
}
