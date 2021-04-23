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
	"net/http"

	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/oauth/pkg/oauth"
)

type (
	// UserInfoUpdateParams contains all the bound params for the user info update operation
	UserInfoUpdateParams struct {
		Profile oauth.Profile `json:"profile,omitempty"`
	}
)

func init() {
	registerRoutes([]route{
		{"/userInfo", http.MethodPut, &UserInfoUpdateParams{}, userInfoUpdate, oauth.Scope(oauth.ScopeOpenID, oauth.ScopeProfile), nil},
		{"/userInfo", http.MethodGet, nil, userInfo, oauth.Scope(oauth.ScopeOpenID, oauth.ScopeProfile), nil},
		{"/userPrincipal", http.MethodGet, nil, userPrincipal, oauth.Scope(oauth.ScopeOpenID, oauth.ScopeProfile), nil},
	})
}

func userInfoUpdate(ctx context.Context, params *UserInfoUpdateParams) api.Responder {
	ctrl := oauth.AuthContext(ctx).Controller
	auth := oauth.AuthContext(ctx)

	if auth.User == nil {
		return oauth.Errorf(oauth.ErrorCodeInvalidRequest, "user context not found")
	}

	if params.Profile.EmailClaim != nil {
		params.Profile.EmailClaim.EmailVerified = nil
	}

	if params.Profile.PhoneClaim != nil {
		params.Profile.PhoneClaim.PhoneNumberVerified = nil
	}

	if err := ctrl.UserUpdate(ctx, auth.User.Profile.Subject, &params.Profile); err != nil {
		return api.Error(err)
	}

	return api.NewResponse().WithStatus(http.StatusNoContent)
}

func userInfo(ctx context.Context) api.Responder {
	auth := oauth.AuthContext(ctx)

	if auth.User == nil {
		return oauth.Errorf(oauth.ErrorCodeInvalidRequest, "user context not found")
	}

	return api.NewResponse(auth.User.Profile)
}

func userPrincipal(ctx context.Context) api.Responder {
	auth := oauth.AuthContext(ctx)

	if auth.Principal == nil {
		return oauth.Errorf(oauth.ErrorCodeInvalidRequest, "user context not found")
	}

	return api.NewResponse(auth.Principal)
}
