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
	"fmt"
	"net/http"
	"net/url"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/oauth/pkg/oauth"
)

type (
	// LoginParams contains all the bound params for the login operation
	LoginParams struct {
		Login        string `json:"login"`
		Password     string `json:"password"`
		RequestToken string `json:"request_token"`
	}
)

func init() {
	registerRoutes([]route{
		{"/login", http.MethodPost, &LoginParams{}, login, nil, nil},
	})
}

// Validate validates LoginParams
func (p LoginParams) Validate() error {
	return validation.Errors{
		"login":         validation.Validate(p.Login, validation.Required),
		"password":      validation.Validate(p.Password, validation.Required),
		"request_token": validation.Validate(p.RequestToken, validation.Required),
	}.Filter()
}

func login(ctx context.Context, params *LoginParams) api.Responder {
	s := serverContext(ctx)

	req := &oauth.AuthRequest{}
	if err := verifyValue(ctx, s.ctrl.TokenValidate, params.RequestToken, req); err != nil {
		return oauth.Error(oauth.ErrorCodeInvalidRequest, err)
	}

	u, err := url.Parse(req.AppURI)
	if err != nil {
		return oauth.Error(oauth.ErrorCodeInvalidRequest, err)
	}

	if time.Unix(req.ExpiresAt, 0).Before(time.Now()) {
		return api.Redirect(u, map[string]string{
			"error":             "bad_request",
			"error_description": "expired request token",
		})
	}

	ctx, err = oauth.ContextFromRequest(ctx, s.ctrl, req)
	if err != nil {
		return api.Redirect(u, map[string]string{
			"error":             "bad_request",
			"error_description": "context verification failed",
		})
	}

	var user *oauth.User

	code, err := s.codes.AuthCodeGet(ctx, params.Password)
	if err == nil {
		s.codes.AuthCodeDestroy(ctx, params.Password)

		user, _, err = s.ctrl.UserGet(ctx, params.Login)
		if err != nil || code.Subject != user.Profile.Subject {
			return api.Redirect(u, map[string]string{
				"error":             "access_denied",
				"error_description": "user authentication failed",
				"request_token":     params.RequestToken,
			})
		}

		if user.Profile.EmailClaim != nil && user.Profile.EmailVerified != nil && !*user.Profile.EmailVerified {
			t := true

			user.Profile.EmailVerified = &t
		}

		if err := s.ctrl.UserUpdate(ctx, user.Profile.Subject, user.Profile); err != nil {
			return api.Redirect(u, map[string]string{
				"error":             "access_denied",
				"error_description": "user authentication failed",
				"request_token":     params.RequestToken,
			})
		}
	} else {
		user, _, err = s.ctrl.UserAuthenticate(ctx, params.Login, params.Password)
		if err != nil {
			return api.Redirect(u, map[string]string{
				"error":             "access_denied",
				"error_description": "user authentication failed",
				"request_token":     params.RequestToken,
			})
		}
	}

	oauth.AuthContext(ctx).User = user

	perms, ok := user.Permissions[req.Audience]
	if !ok {
		return api.Redirect(u, map[string]string{
			"error":             "access_denied",
			"error_description": "user authorization failed",
		})
	}

	if len(req.Scope) == 0 {
		req.Scope = perms
	}

	if !perms.Every(req.Scope...) {
		return api.Redirect(u, map[string]string{
			"error":             "access_denied",
			"error_description": "user authorization failed",
		})
	}

	r, w := api.Request(ctx)

	session, err := sessionStore(ctx).SessionCreate(ctx, r)
	if err != nil {
		return api.Redirect(u, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})
	}

	session.Set(fmt.Sprintf("scope:%s", oauth.AuthContext(ctx).Audience.Name()), []string(req.Scope))

	if err := session.Write(w); err != nil {
		return api.Redirect(u, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})
	}

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

	u, _ = url.Parse(req.RedirectURI)

	q := u.Query()

	q.Set("code", authCode.Code)

	if req.State != nil {
		q.Set("state", *req.State)
	}

	u.RawQuery = q.Encode()

	return api.Redirect(u)
}
