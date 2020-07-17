/*
 * Copyright (C) 2020 Atomic Media Foundation
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file in the root of this
 * workspace for details.
 */

package rest

import (
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/libatomic/oauth/pkg/oauth"
)

// AuthorizeRequest implements the auth.Authorizer interface
func (s *Server) AuthorizeRequest(r *http.Request, scope ...[]string) (*jwt.Token, interface{}, error) {
	var claims jwt.MapClaims

	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

	token, err := jwt.Parse(bearer, func(token *jwt.Token) (interface{}, error) {
		claims = token.Claims.(jwt.MapClaims)

		switch token.Method.(type) {
		case *jwt.SigningMethodHMAC:
			aud, err := s.ctrl.AudienceGet(claims["aud"].(string))
			if err != nil {
				return nil, err
			}

			return []byte(aud.TokenSecret), nil
		case *jwt.SigningMethodRSA:
			return &s.signingKey.PublicKey, nil

		default:
			return nil, oauth.ErrUnsupportedAlogrithm
		}
	})
	if err != nil {
		return nil, nil, err
	}

	if !token.Valid {
		return nil, nil, oauth.ErrInvalidToken
	}

	scopes := strings.Fields(claims["scope"].(string))

	allowed := false
	for _, s := range scope {
		if every(scopes, s...) {
			allowed = true
			break
		}
	}

	if !allowed {
		return nil, nil, oauth.ErrAccessDenied
	}

	var prin interface{}

	if sub, ok := claims["sub"].(string); ok {
		if !strings.HasSuffix(sub, "@applications") {
			prin, err = s.ctrl.UserGet(sub)
			if err != nil {
				return nil, nil, oauth.ErrAccessDenied
			}
		} else {
			prin, err = s.ctrl.ApplicationGet(strings.TrimSuffix(sub, "@applications"))
			if err != nil {
				return nil, nil, oauth.ErrAccessDenied
			}
		}
	}

	return token, prin, nil
}
