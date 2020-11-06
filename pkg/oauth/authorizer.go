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

package oauth

import (
	"context"
	"crypto/rsa"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/libatomic/api/pkg/api"
)

type (
	// Authorizer is an oauth authorizer interface
	Authorizer interface {
		Authorize(opts ...AuthOption) api.Authorizer
	}

	authorizer struct {
		ctrl        Controller
		publicKey   *rsa.PublicKey
		tokenSecret []byte
	}

	// AuthOption is an authorizer option
	AuthOption func(a *authOptions)

	// AuthorizerOption is an authorizer option
	AuthorizerOption func(a *authorizer)

	authOptions struct {
		scope []Permissions
		roles []Permissions
	}
)

// NewAuthorizer returns a new oauth authorizer
func NewAuthorizer(ctrl Controller, opts ...AuthorizerOption) Authorizer {
	auth := &authorizer{
		ctrl: ctrl,
	}

	for _, o := range opts {
		o(auth)
	}
	return auth
}

// WithPublicKey sets the public key for the authorizer
func WithPublicKey(k *rsa.PublicKey) AuthorizerOption {
	return func(a *authorizer) {
		a.publicKey = k
	}
}

// WithTokenSecret sets the public key for the authorizer
func WithTokenSecret(s []byte) AuthorizerOption {
	return func(a *authorizer) {
		a.tokenSecret = s
	}
}

func (a *authorizer) Authorize(opts ...AuthOption) api.Authorizer {
	o := &authOptions{}

	for _, opt := range opts {
		opt(o)
	}

	return func(r *http.Request) (context.Context, error) {
		var claims jwt.MapClaims
		var err error
		var aud *Audience

		ctx := r.Context()

		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

		token, err := jwt.Parse(bearer, func(token *jwt.Token) (interface{}, error) {
			claims = token.Claims.(jwt.MapClaims)

			id, ok := claims["aud"].(string)
			if !ok {
				return nil, ErrAccessDenied
			}
			aud, err = a.ctrl.AudienceGet(r.Context(), id)
			if err != nil {
				return nil, err
			}

			switch token.Method.(type) {
			case *jwt.SigningMethodHMAC:
				if a.tokenSecret != nil {
					return a.tokenSecret, nil
				}
				return []byte(a.tokenSecret), nil

			case *jwt.SigningMethodRSA:
				if a.publicKey == nil {
					return nil, ErrUnsupportedAlogrithm
				}
				return a.publicKey, nil

			default:
				if token.Method == jwt.SigningMethodNone {
					return "", nil
				}
				return nil, ErrUnsupportedAlogrithm
			}
		})
		if err != nil {
			return nil, err
		}

		if !token.Valid {
			return nil, ErrInvalidToken
		}

		scopes := Permissions(strings.Fields(claims["scope"].(string)))

		allowed := true

		// check scopes
		if len(o.scope) > 0 {
			allowed = false
		}

		for _, s := range o.scope {
			if scopes.Every(s...) {
				allowed = true
				break
			}
		}

		if !allowed {
			return nil, ErrAccessDenied
		}

		c := Context{
			Audience: aud,
			Token:    token,
		}

		if azp, ok := claims["azp"].(string); ok {
			app, err := a.ctrl.ApplicationGet(NewContext(ctx, aud), azp)
			if err != nil {
				return nil, ErrAccessDenied
			}
			c.Application = app
		}

		if sub, ok := claims["sub"].(string); ok && !strings.HasSuffix(sub, "@applications") {
			user, prin, err := a.ctrl.UserGet(NewContext(ctx, c), sub)
			if err != nil {
				return nil, ErrAccessDenied
			}

			// check roles
			if len(o.roles) > 0 {
				roles, ok := user.Roles[aud.Name]
				if !ok {
					return nil, ErrAccessDenied
				}

				allowed := false

				for _, r := range o.roles {
					if roles.Some(r...) {
						allowed = true
						break
					}
				}

				if !allowed {
					return nil, ErrAccessDenied
				}
			}

			c.User = user
			c.Principal = prin
		}

		return NewContext(ctx, c), nil
	}
}

// WithScope will create an api.Authorizer with the scope
func WithScope(scope ...Permissions) AuthOption {
	return func(o *authOptions) {
		o.scope = scope
	}
}

// WithRoles enforces the user roles
func WithRoles(roles ...Permissions) AuthOption {
	return func(o *authOptions) {
		o.roles = roles
	}
}
