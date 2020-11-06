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
	"time"

	"github.com/go-openapi/strfmt"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/oauth/pkg/oauth"
)

type (
	// SignupParams contains all the bound params for the signup operation
	SignupParams struct {
		Email        string  `json:"email"`
		InviteCode   *string `json:"invite_code"`
		Login        string  `json:"login"`
		Name         *string `json:"name"`
		Password     string  `json:"password"`
		RequestToken string  `json:"request_token"`
	}
)

func init() {
	registerRoutes([]route{
		{"/signup", http.MethodPost, &SignupParams{}, signup, nil},
	})
}

// Validate validates SignupParams
func (p SignupParams) Validate() error {
	return validation.Errors{
		"email":         validation.Validate(p.Email, validation.Required, is.EmailFormat),
		"invite_code":   validation.Validate(p.InviteCode, validation.NilOrNotEmpty),
		"login":         validation.Validate(p.Login, validation.Required),
		"name":          validation.Validate(p.Name, validation.NilOrNotEmpty),
		"password":      validation.Validate(p.Password, validation.Required),
		"request_token": validation.Validate(p.RequestToken, validation.Required),
	}.Filter()
}

func signup(ctx context.Context, params *SignupParams) api.Responder {
	s := serverContext(ctx)

	req := &oauth.AuthRequest{}
	if err := verifyValue(ctx, s.ctrl, params.RequestToken, req); err != nil {
		return api.Error(err).WithStatus(http.StatusBadRequest)
	}
	if time.Unix(req.ExpiresAt, 0).Before(time.Now()) {
		return api.StatusErrorf(http.StatusUnauthorized, "expired request token")
	}

	octx, err := oauth.ContextFromRequest(ctx, s.ctrl, req)
	if err != nil {
		return api.StatusError(http.StatusInternalServerError, err)
	}

	if _, err := s.ctrl.UserCreate(octx, params.Login, params.Password, &oauth.Profile{
		Name:  safestr(params.Name),
		Email: strfmt.Email(params.Email),
	}, safestr(params.InviteCode)); err != nil {
		return api.StatusError(http.StatusBadRequest, err)
	}

	loginParams := &LoginParams{
		Login:        params.Login,
		Password:     params.Password,
		RequestToken: params.RequestToken,
	}

	return login(ctx, loginParams)
}
