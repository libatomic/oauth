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
		RedirectURI  *oauth.URI `json:"redirect_uri"`
		State        *string    `json:"state,omitempty"`
	}
)

func init() {
	registerRoutes([]route{
		{"/session", http.MethodGet, &SessionParams{}, session, oauth.Scope(oauth.ScopeSession), []oauth.AuthOption{oauth.WithErrorPassthrough()}},
	})
}

func session(ctx context.Context, params *SessionParams) api.Responder {
	s := serverContext(ctx)

	octx := oauth.AuthContext(ctx)

	req := &oauth.AuthRequest{}

	if uri, ok := octx.Token["rdr"].(string); ok {
		req.AppURI = uri
		req.RedirectURI = uri

		auds := octx.Token.Audience()
		if len(auds) > 0 {
			req.Audience = auds[0]
		}
		sub := octx.Token.Subject()
		req.Subject = &sub
		req.Scope = octx.Token.Scope()
		req.ExpiresAt = octx.Token.ExpiresAt().Unix()

	} else if err := verifyValue(ctx, s.ctrl.TokenValidate, params.RequestToken, req); err != nil {
		return oauth.Error(oauth.ErrorCodeAccessDenied, err)
	}

	u, _ := url.Parse(req.AppURI)

	if u.Path == "" {
		u.Path = "/"
	}

	// check for authorization errors so we can return the to the redirect
	if octx.Error != nil {
		if errors.Is(octx.Error, oauth.ErrAccessDenied) {
			return ErrUnauthorized(u, octx.Error.Error())
		}
		return ErrBadRequest(u, octx.Error.Error())
	}

	if time.Unix(req.ExpiresAt, 0).Before(time.Now()) {
		return ErrExpiredRequestToken(u)
	}

	if req.Subject == nil {
		return ErrInvalidContext(u)
	}

	if *req.Subject != octx.User.Profile.Subject {
		return ErrInvalidContext(u)
	}

	user := octx.User

	r, w := api.Request(ctx)

	session, err := sessionStore(ctx).SessionCreate(oauth.NewContext(ctx, user), r)
	if err != nil {
		return ErrServerError(u, "%s: failed to create session", err)
	}

	if err := session.Write(w); err != nil {
		return ErrServerError(u, "%s: failed to write session", err)
	}

	u, _ = url.Parse(req.RedirectURI)

	if u.Path == "" {
		u.Path = "/"
	}

	if params.AuthCode {
		authCode := &oauth.AuthCode{
			AuthRequest:       *req,
			Subject:           user.Profile.Subject,
			SessionID:         session.ID(),
			UserAuthenticated: true,
		}
		if err := codeStore(ctx).AuthCodeCreate(ctx, authCode); err != nil {
			return ErrServerError(u, "%s: failed to create auth code", err)
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
