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

	"github.com/asaskevich/govalidator"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/oauth/pkg/oauth"
)

type (
	// SignupParams contains all the bound params for the signup operation
	SignupParams struct {
		Email        *string `json:"email,omitempty"`
		InviteCode   *string `json:"invite_code"`
		Login        string  `json:"login"`
		Name         *string `json:"name"`
		Password     *string `json:"password"`
		RequestToken string  `json:"request_token"`
	}
)

func init() {
	registerRoutes([]route{
		{"/signup", http.MethodPost, &SignupParams{}, signup, nil, nil},
	})
}

// Validate validates SignupParams
func (p SignupParams) Validate() error {
	return validation.Errors{
		"email":         validation.Validate(p.Email, validation.NilOrNotEmpty, is.EmailFormat),
		"invite_code":   validation.Validate(p.InviteCode, validation.NilOrNotEmpty),
		"login":         validation.Validate(p.Login, validation.Required),
		"name":          validation.Validate(p.Name, validation.Required),
		"password":      validation.Validate(p.Password, validation.NilOrNotEmpty),
		"request_token": validation.Validate(p.RequestToken, validation.Required),
	}.Filter()
}

func signup(ctx context.Context, params *SignupParams) api.Responder {
	s := serverContext(ctx)

	log := api.Log(ctx).WithField("operation", "signup")

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
			"error_description": err.Error(),
		})
	}

	if govalidator.IsEmail(params.Login) && params.Email == nil {
		params.Email = &params.Login
	}

	user, err := s.ctrl.UserCreate(ctx, params.Login, params.Password, &oauth.Profile{
		Name: safestr(params.Name),
		EmailClaim: &oauth.EmailClaim{
			Email: params.Email,
		},
	}, safestr(params.InviteCode))
	if err != nil {
		return api.Redirect(u, err)
	}

	u, _ = url.Parse(req.RedirectURI)
	q := u.Query()

	if err := VerifySend(oauth.NewContext(ctx, user), &VerifySendParams{
		Method:      oauth.NotificationChannelEmail,
		Signup:      true,
		scope:       req.Scope,
		redirectURI: &req.RedirectURI,
	}); err != nil {
		err = fmt.Errorf("failed to send email verification to user %s: %s", user.Login, err.Error())

		log.Error(err.Error())

		q.Set("error", "internal_server_error")
		q.Set("error_description", err.Error())
	}

	if params.Password != nil {
		loginParams := &LoginParams{
			Login:        params.Login,
			Password:     *params.Password,
			RequestToken: params.RequestToken,
		}

		return login(ctx, loginParams)
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
	q.Set("code", authCode.Code)

	if req.State != nil {
		q.Set("state", *req.State)
	}

	u.RawQuery = q.Encode()

	return api.Redirect(u)
}
