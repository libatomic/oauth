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
		{"/login", http.MethodPost, &LoginParams{}, login, nil},
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
		return api.Error(err).WithStatus(http.StatusBadRequest)
	}

	if time.Unix(req.ExpiresAt, 0).Before(time.Now()) {
		return api.Errorf("expired request token").WithStatus(http.StatusUnauthorized)
	}

	u, _ := url.Parse(req.AppURI)

	ctx, err := oauth.ContextFromRequest(ctx, s.ctrl, req)
	if err != nil {
		return api.Redirect(u, map[string]string{
			"error":             "bad_request",
			"error_description": "context verification failed",
		})
	}

	user, _, err := s.ctrl.UserAuthenticate(ctx, params.Login, params.Password)
	if err != nil {
		return api.Redirect(u, map[string]string{
			"error":             "access_denied",
			"error_description": "user authentication failed",
			"request_token":     params.RequestToken,
		})
	}

	oauth.GetContext(ctx).User = user

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
