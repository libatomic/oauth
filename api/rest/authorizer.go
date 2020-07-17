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

type (
	authContext struct {
		app  *oauth.Application
		user *oauth.User
		prin interface{}
	}
)

// AuthorizeRequest implements the auth.Authorizer interface
func (s *Server) AuthorizeRequest(r *http.Request, scope ...[]string) (*jwt.Token, oauth.Context, error) {
	var claims jwt.MapClaims

	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

	token, err := jwt.Parse(bearer, func(token *jwt.Token) (interface{}, error) {
		claims = token.Claims.(jwt.MapClaims)

		switch token.Method.(type) {
		case *jwt.SigningMethodHMAC:
			id, ok := claims["aud"].(string)
			if !ok {
				return nil, oauth.ErrAccessDenied
			}
			aud, err := s.ctrl.AudienceGet(id)
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

	c := &authContext{}

	if sub, ok := claims["sub"].(string); ok && !strings.HasSuffix(sub, "@applications") {
		user, prin, err := s.ctrl.UserGet(sub)
		if err != nil {
			return nil, nil, oauth.ErrAccessDenied
		}
		c.user = user
		c.prin = prin
	}

	if azp, ok := claims["azp"].(string); ok {
		app, err := s.ctrl.ApplicationGet(azp)
		if err != nil {
			return nil, nil, oauth.ErrAccessDenied
		}
		c.app = app
	}

	return token, c, nil
}

func (c *authContext) User() *oauth.User {
	return c.user
}

func (c *authContext) Application() *oauth.Application {
	return c.app
}

func (c *authContext) Principal() interface{} {
	return c.prin
}
