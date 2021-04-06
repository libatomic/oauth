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
	"path"
	"strings"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/oauth/pkg/oauth"
)

type (
	// VerifyParams contains the email verify params
	VerifyParams struct {
		RedirectURI string `json:"redirect_uri"`
	}

	// VerifySendParams are the params for the verification send method
	VerifySendParams struct {
		Method oauth.NotificationChannel `json:"method"`
		Signup bool                      `json:"-"`
		scope  oauth.Permissions
	}

	verifyNotification struct {
		sub     string
		uri     oauth.URI
		channel oauth.NotificationChannel
		signup  bool
		context map[string]interface{}
	}
)

func init() {
	registerRoutes([]route{
		{"/verify", http.MethodGet, &VerifyParams{}, verify, oauth.Scope(oauth.ScopeOpenID, oauth.ScopeProfile), nil},
		{"/verify", http.MethodPost, &VerifySendParams{}, verifySend, oauth.Scope(oauth.ScopeOpenID, oauth.ScopeProfile), nil},
	})
}

// Validate validates UserEmailVerifyParams
func (p VerifyParams) Validate() error {
	return validation.Errors{
		"redirect_uri": validation.Validate(p.RedirectURI, validation.Required, is.RequestURI),
	}.Filter()
}

func verify(ctx context.Context, params *VerifyParams) api.Responder {
	ctrl := oauth.AuthContext(ctx).Controller
	auth := oauth.AuthContext(ctx)

	if auth.Principal == nil {
		return api.StatusErrorf(http.StatusUnauthorized, "invalid token")
	}

	r, _ := api.Request(ctx)

	u, err := EnsureURI(params.RedirectURI, auth.Application.RedirectUris[auth.Audience.Name()], r)
	if err != nil {
		return api.Errorf("unauthorized redirect uri").WithStatus(http.StatusUnauthorized)
	}

	if auth.Token.Scope().Contains(oauth.ScopeEmailVerify) {
		verifed := true
		if err := ctrl.UserUpdate(ctx, auth.User.Profile.Subject, &oauth.Profile{
			EmailClaim: &oauth.EmailClaim{
				EmailVerified: &verifed,
			},
		}); err != nil {
			return api.Redirect(u, map[string]string{
				"error":             "server_error",
				"error_description": err.Error(),
			})
		}
	} else {
		return api.Redirect(u, map[string]string{
			"error":             "access_denied",
			"error_description": "insufficient scope",
		})
	}

	if auth.Token.Scope().Contains(oauth.ScopeSession) {
		user := auth.User

		r, w := api.Request(ctx)

		session, err := sessionStore(ctx).SessionCreate(oauth.NewContext(ctx, user), r)
		if err != nil {
			return api.ErrorRedirect(u, http.StatusInternalServerError, "%s: failed to create session", err)
		}

		if err := session.Write(w); err != nil {
			return api.ErrorRedirect(u, http.StatusInternalServerError, "%s: failed to write session", err)
		}

		authCode := &oauth.AuthCode{
			AuthRequest:       *auth.Request,
			Subject:           user.Profile.Subject,
			SessionID:         session.ID(),
			UserAuthenticated: true,
		}
		if err := codeStore(ctx).AuthCodeCreate(ctx, authCode); err != nil {
			return api.ErrorRedirect(u, http.StatusInternalServerError, "%s: failed to create auth code", err)
		}

		q := u.Query()

		q.Set("code", authCode.Code)

		u.RawQuery = q.Encode()
	}

	return api.Redirect(u)
}

func verifySend(ctx context.Context, params *VerifySendParams) api.Responder {
	if err := VerifySend(ctx, params); err != nil {
		return api.Error(err)
	}

	return api.NewResponse().WithStatus(http.StatusNoContent)
}

// VerifySend sends a verification to the user
func VerifySend(ctx context.Context, params *VerifySendParams) error {
	ctrl := oauth.AuthContext(ctx).Controller
	auth := oauth.AuthContext(ctx)

	r, _ := api.Request(ctx)

	link, err := oauth.URI(
		fmt.Sprintf("https://%s%s",
			r.Host,
			path.Clean(path.Join(path.Dir(r.URL.Path), "verify")))).Parse()
	if err != nil {
		return err
	}

	iss := issuer(ctx)

	scope := []string{oauth.ScopeOpenID, oauth.ScopeProfile, oauth.ScopeEmailVerify}

	if params.Signup {
		scope = append(scope, oauth.ScopeSession)
	}

	if len(params.scope) > 0 {
		scope = append(scope, params.scope...)
	}

	claims := oauth.Claims{
		"iss":   iss,
		"use":   "access",
		"iat":   time.Now().Unix(),
		"aud":   auth.Audience.Name(),
		"sub":   auth.User.Profile.Subject,
		"scope": strings.Join(scope, " "),
		"exp":   time.Now().Add(time.Hour * 24).Unix(),
		"azp":   auth.Application.ClientID,
	}

	token, err := ctrl.TokenFinalize(ctx, claims)
	if err != nil {
		return err
	}
	q := link.Query()
	q.Set("access_token", token)
	link.RawQuery = q.Encode()

	if err := ctrl.UserNotify(ctx, &verifyNotification{
		sub:     auth.User.Profile.Subject,
		channel: params.Method,
		uri:     oauth.URI(link.String()),
		signup:  params.Signup,
	}); err != nil {
		return err
	}

	return nil
}

func (n verifyNotification) Type() oauth.NotificationType {
	if n.signup {
		return oauth.NotificationTypeSignup
	}
	return oauth.NotificationTypeVerify
}

func (n verifyNotification) Subject() string {
	return n.sub
}

func (n verifyNotification) URI() *oauth.URI {
	return &n.uri
}

func (n verifyNotification) Code() *string {
	return nil
}

func (n verifyNotification) Channels() oauth.NotificationChannels {
	return []oauth.NotificationChannel{oauth.NotificationChannel(n.channel)}
}

func (n verifyNotification) Context() map[string]interface{} {
	if n.context == nil {
		return map[string]interface{}{}
	}
	return n.context
}
