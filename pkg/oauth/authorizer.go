/*
 * Copyright (C) 2020 Atomic Media Foundation
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file in the root of this
 * workspace for details.
 */

package oauth

import (
	"crypto/rsa"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/libatomic/api/pkg/api"
)

// NewAuthorizer returns a new oauth authorizer
func NewAuthorizer(ctrl Controller, privKey *rsa.PrivateKey) Authorizer {
	return func(scope ...Permissions) api.Authorizer {
		return func(r *http.Request) (interface{}, error) {
			var claims jwt.MapClaims
			var err error
			var aud *Audience

			bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

			token, err := jwt.Parse(bearer, func(token *jwt.Token) (interface{}, error) {
				claims = token.Claims.(jwt.MapClaims)

				switch token.Method.(type) {
				case *jwt.SigningMethodHMAC:
					id, ok := claims["aud"].(string)
					if !ok {
						return nil, ErrAccessDenied
					}
					aud, err = ctrl.AudienceGet(id)
					if err != nil {
						return nil, err
					}

					return []byte(aud.TokenSecret), nil

				case *jwt.SigningMethodRSA:
					return &privKey.PublicKey, nil

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

			if aud == nil {
				id, ok := claims["aud"].(string)
				if !ok {
					return nil, ErrAccessDenied
				}
				aud, err = ctrl.AudienceGet(id)
				if err != nil {
					return nil, err
				}
			}
			scopes := Permissions(strings.Fields(claims["scope"].(string)))

			allowed := false
			for _, s := range scope {
				if scopes.Every(s...) {
					allowed = true
					break
				}
			}

			if !allowed {
				return nil, ErrAccessDenied
			}

			c := &authContext{
				aud:   aud,
				token: token,
			}

			if azp, ok := claims["azp"].(string); ok {
				app, err := ctrl.ApplicationGet(azp)
				if err != nil {
					return nil, ErrAccessDenied
				}
				c.app = app
			}

			if sub, ok := claims["sub"].(string); ok && !strings.HasSuffix(sub, "@applications") {
				user, prin, err := ctrl.UserGet(c, sub)
				if err != nil {
					return nil, ErrAccessDenied
				}
				c.user = user
				c.prin = prin
			}

			return c, nil
		}
	}
}
