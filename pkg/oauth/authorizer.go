/*
 * Copyright (C) 2020 Atomic Media Foundation
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file in the root of this
 * workspace for details.
 */

package oauth

import (
	"context"
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
		ctrl Controller
	}

	// AuthOption is an authorizer option
	AuthOption func(a *authOptions)

	authOptions struct {
		scope []Permissions
	}
)

// NewAuthorizer returns a new oauth authorizer
func NewAuthorizer(ctrl Controller) Authorizer {
	return &authorizer{
		ctrl: ctrl,
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

				return []byte(aud.TokenSecret), nil

			case *jwt.SigningMethodRSA:
				return a.ctrl.TokenPublicKey(NewContext(ctx, Context{Audience: aud}))

			default:
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

		allowed := false
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
			app, err := a.ctrl.ApplicationGet(ctx, azp)
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
