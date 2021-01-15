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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/apex/log"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/oauth/pkg/oauth"
)

type (
	// PasswordCreateParams is the input to the password get route
	PasswordCreateParams struct {
		Login        string                     `json:"login"`
		Notify       oauth.NotificationChannels `json:"notify"`
		Type         PasswordType               `json:"type"`
		RequestToken *string                    `json:"request_token,omitempty"`
		AppURI       *oauth.URI                 `json:"app_uri,omitempty"`
		RedirectURI  *oauth.URI                 `json:"redirect_uri,omitempty"`
		CodeVerifier *string                    `json:"code_verifier,omitempty"`
	}

	// PasswordUpdateParams are used by the password update route
	PasswordUpdateParams struct {
		Password    string     `json:"password"`
		ResetCode   string     `json:"reset_code"`
		RedirectURI *oauth.URI `json:"redirect_uri"`
	}

	// PasswordType defines a password type
	PasswordType string

	passwordNotification struct {
		sub          string
		passwordType PasswordType
		uri          *oauth.URI
		code         string
		notify       oauth.NotificationChannels
	}
)

const (
	// PasswordTypeLink is a magic password link
	PasswordTypeLink PasswordType = "link"

	// PasswordTypeCode is a one-time use password code
	PasswordTypeCode PasswordType = "code"

	// PasswordTypeReset sends both a link with the password scope and a code
	PasswordTypeReset PasswordType = "reset"
)

var (
	passcodeAlpha = [...]byte{'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'}
)

func init() {
	registerRoutes([]route{
		{"/password", http.MethodPost, &PasswordCreateParams{}, passwordCreate, oauth.Scope(oauth.ScopePassword), []oauth.AuthOption{oauth.WithOptional()}},
		{"/password", http.MethodPut, &PasswordUpdateParams{}, passwordUpdate, oauth.Scope(oauth.ScopePassword), nil},
	})
}

// Validate validates the PasswordType
func (p PasswordType) Validate() error {
	return validation.Validate(string(p), validation.In("link", "code", "reset"))
}

// Validate validates PasswordGetInput
func (p PasswordCreateParams) Validate() error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.Login, validation.Required),
		validation.Field(&p.Type, validation.Required),
		validation.Field(&p.Notify, validation.Required, validation.Each(validation.In(oauth.NotificationChannelEmail, oauth.NotificationChannelPhone))),
		validation.Field(&p.RequestToken, validation.NilOrNotEmpty),
		validation.Field(&p.AppURI, validation.NilOrNotEmpty, is.RequestURI),
		validation.Field(&p.RedirectURI, validation.NilOrNotEmpty, is.RequestURI),
		validation.Field(&p.CodeVerifier, validation.NilOrNotEmpty),
	)
}

// Validate validates PasswordGetInput
func (p PasswordUpdateParams) Validate() error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.Password, validation.Required),
		validation.Field(&p.ResetCode, validation.Required),
		validation.Field(&p.RedirectURI, validation.NilOrNotEmpty, is.RequestURI),
	)
}

func passwordCreate(ctx context.Context, params *PasswordCreateParams) api.Responder {
	s := serverContext(ctx)

	var req *oauth.AuthRequest
	var user *oauth.User
	var u *url.URL

	if params.RequestToken != nil {
		var err error

		req = &oauth.AuthRequest{}
		if err := verifyValue(ctx, s.ctrl.TokenValidate, *params.RequestToken, req); err != nil {
			return api.Error(err).WithStatus(http.StatusBadRequest)
		}

		u, _ = url.Parse(req.AppURI)

		if time.Unix(req.ExpiresAt, 0).Before(time.Now()) {
			return api.Redirect(u, map[string]string{
				"error":             "bad_request",
				"error_description": "expired request token",
			})
		}

		if params.CodeVerifier == nil {
			return api.Errorf("code_verifier: cannot be blank")
		}

		sum := sha256.Sum256([]byte(*params.CodeVerifier))
		check := base64.RawURLEncoding.EncodeToString(sum[:])

		if req.CodeChallenge != check {
			return api.Redirect(u, map[string]string{
				"error":             "access_denied",
				"error_description": "invalid code",
			})
		}

		ctx, err = oauth.ContextFromRequest(ctx, s.ctrl, req)
		if err != nil {
			return api.Redirect(u, map[string]string{
				"error":             "bad_request",
				"error_description": "context verification failed",
			})
		}

		user, _, err = s.ctrl.UserGet(ctx, params.Login)
		if err != nil {
			return api.Redirect(u, map[string]string{
				"error":             "access_denied",
				"error_description": "user does not exist",
			})
		}

		ctx = oauth.NewContext(ctx, user)

	} else {
		if params.AppURI == nil || params.RedirectURI == nil {
			return api.StatusErrorf(http.StatusBadRequest, "redirect_uri: required; app_uri: required")
		}

		octx := oauth.AuthContext(ctx)

		if octx.User == nil {
			return api.StatusErrorf(http.StatusUnauthorized, "user session invalid")
		}

		user = octx.User

		req = octx.Request
		req.RedirectURI = string(*params.RedirectURI)

		_, err := url.Parse(string(*params.RedirectURI))
		if err != nil {
			return api.StatusErrorf(http.StatusUnauthorized, "invalid redirect_uri")
		}

		u, err = url.Parse(string(*params.AppURI))
		if err != nil {
			return api.StatusErrorf(http.StatusUnauthorized, "invalid app_uri")
		}
	}

	octx := oauth.AuthContext(ctx)

	// Links are good for 1 hour, codes are good for 10 minutes
	if params.Type == PasswordTypeLink {
		req.ExpiresAt = time.Now().Add(time.Hour * 1).Unix()
	} else {
		req.ExpiresAt = time.Now().Add(time.Minute * 10).Unix()
	}

	req.Subject = &user.Profile.Subject

	note := passwordNotification{
		sub:          user.Profile.Subject,
		passwordType: params.Type,
		notify:       params.Notify,
	}

	r, _ := api.Request(ctx)

	issuer := fmt.Sprintf("https://%s%s", r.Host, path.Clean(path.Join(path.Dir(r.URL.Path), "/.well-known/jwks.json")))

	link, err := oauth.URI(
		fmt.Sprintf("https://%s%s",
			r.Host,
			path.Clean(path.Join(path.Dir(r.URL.Path), "session")))).Parse()
	if err != nil {
		log.Error(err.Error())

		return api.Redirect(u, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})
	}
	q := link.Query()

	switch params.Type {
	case PasswordTypeReset:
		if !req.Scope.Contains(oauth.ScopePassword) {
			req.Scope = append(req.Scope, oauth.ScopePassword)
		}

		authCode := &oauth.AuthCode{
			AuthRequest: *req,
			Subject:     user.Profile.Subject,
		}
		if err := codeStore(ctx).AuthCodeCreate(ctx, authCode); err != nil {
			return api.Redirect(u, map[string]string{
				"error":             "server_error",
				"error_description": err.Error(),
			})
		}
		ru, _ := url.Parse(req.RedirectURI)

		q := ru.Query()
		q.Add("reset_code", authCode.Code)

		ru.RawQuery = q.Encode()

		req.RedirectURI = ru.String()

		fallthrough

	case PasswordTypeLink:
		reqToken, err := signValue(ctx, s.ctrl.TokenFinalize, req)
		if err != nil {
			return api.Redirect(u, map[string]string{
				"error":             "server_error",
				"error_description": err.Error(),
			})
		}

		claims := oauth.Claims{
			"iss":   issuer,
			"use":   "access",
			"iat":   time.Now().Unix(),
			"aud":   octx.Audience.Name(),
			"sub":   user.Profile.Subject,
			"scope": oauth.ScopeSession,
			"exp":   req.ExpiresAt,
			"azp":   octx.Application.ClientID,
		}

		token, err := s.ctrl.TokenFinalize(ctx, claims)
		if err != nil {
			return api.StatusError(http.StatusInternalServerError, err)
		}

		q.Set("access_token", token)
		q.Set("request_token", reqToken)

		if params.Type == PasswordTypeLink {
			q.Set("auth_code", "true")
		}

		link.RawQuery = q.Encode()

		note.uri = oauth.URI(link.String()).Ptr()
	case PasswordTypeCode:
		// TODO: 2FA
	}

	if err := s.ctrl.UserNotify(ctx, note); err != nil {
		return api.Redirect(u, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})
	}

	return api.Redirect(u)
}

func passwordUpdate(ctx context.Context, params *PasswordUpdateParams) api.Responder {
	s := serverContext(ctx)

	octx := oauth.AuthContext(ctx)

	code, err := codeStore(ctx).AuthCodeGet(ctx, params.ResetCode)
	if err != nil {
		return api.StatusErrorf(http.StatusUnauthorized, "invalid reset code")
	}

	if octx.User.Profile.Subject != code.Subject {
		return api.StatusErrorf(http.StatusUnauthorized, "subject mismatch")
	}

	if err := s.ctrl.UserSetPassword(ctx, octx.User.Profile.Subject, params.Password); err != nil {
		return api.Error(err)
	}

	codeStore(ctx).AuthCodeDestroy(ctx, code.Code)

	if params.RedirectURI != nil {
		u, _ := url.Parse(string(*params.RedirectURI))

		return api.Redirect(u)
	}

	return api.NewResponse().WithStatus(http.StatusNoContent)
}

func (n passwordNotification) Type() oauth.NotificationType {
	if n.passwordType == PasswordTypeReset {
		return oauth.NotificationTypePasswordReset
	}
	return oauth.NotificationTypePassword
}

func (n passwordNotification) Subject() string {
	return n.sub
}

func (n passwordNotification) URI() *oauth.URI {
	return n.uri
}

func (n passwordNotification) PasswordType() PasswordType {
	return n.passwordType
}

func (n passwordNotification) Code() string {
	return n.code
}

func (n passwordNotification) Channels() oauth.NotificationChannels {
	return n.notify
}

func generatePasscode(max int) string {
	b := make([]byte, max)
	n, err := io.ReadAtLeast(rand.Reader, b, max)
	if n != max {
		panic(err)
	}
	for i := 0; i < len(b); i++ {
		b[i] = passcodeAlpha[int(b[i])%len(passcodeAlpha)]
	}
	return string(b)
}
