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
	"net/url"
	"time"

	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/oauth/pkg/oauth"
)

type (
	// SessionParams is the session request parameters
	SessionParams struct {
		RequestToken string     `json:"request_token"`
		AuthCode     bool       `json:"auth_code"`
		RedirectURI  *oauth.URI `json:"redirect_ur"`
		State        *string    `json:"state,omitempty"`
	}
)

func init() {
	registerRoutes([]route{
		{"/session", http.MethodGet, &SessionParams{}, session, oauth.Scope(oauth.ScopeSession), nil},
	})
}

func session(ctx context.Context, params *SessionParams) api.Responder {
	s := serverContext(ctx)

	req := &oauth.AuthRequest{}
	if err := verifyValue(ctx, s.ctrl.TokenValidate, params.RequestToken, req); err != nil {
		return api.Error(err).WithStatus(http.StatusBadRequest)
	}

	u, _ := url.Parse(req.AppURI)

	if time.Unix(req.ExpiresAt, 0).Before(time.Now()) {
		return api.Redirect(u, map[string]string{
			"error":             "bad_request",
			"error_description": "expired request token",
		})
	}

	ctx, err := oauth.ContextFromRequest(ctx, s.ctrl, req)
	if err != nil {
		return api.Redirect(u, map[string]string{
			"error":             "bad_request",
			"error_description": "context verification failed",
		})
	}

	if req.Subject == nil {
		return api.Redirect(u, map[string]string{
			"error":             "bad_request",
			"error_description": "context verification failed, missing subject",
		})
	}

	user, _, err := s.ctrl.UserGet(ctx, *req.Subject)
	if err != nil {
		return api.Redirect(u, map[string]string{
			"error":             "access_denied",
			"error_description": "user authentication failed",
			"request_token":     params.RequestToken,
		})
	}

	r, w := api.Request(ctx)

	session, err := sessionStore(ctx).SessionCreate(oauth.NewContext(ctx, user), r)
	if err != nil {
		return api.Redirect(u, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})
	}

	if err := session.Write(w); err != nil {
		return api.Redirect(u, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})
	}

	u, _ = url.Parse(req.RedirectURI)

	if params.AuthCode {
		authCode := &oauth.AuthCode{
			AuthRequest:       *req,
			Subject:           user.Profile.Subject,
			SessionID:         session.ID(),
			UserAuthenticated: true,
		}
		if err := codeStore(ctx).AuthCodeCreate(ctx, authCode); err != nil {
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
	}

	return api.Redirect(u)
}
