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
		app   *oauth.Application
		aud   *oauth.Audience
		user  *oauth.User
		prin  interface{}
		token *jwt.Token
		req   *oauth.AuthRequest
	}
)

// AuthorizeRequest implements the auth.Authorizer interface
func (s *Server) AuthorizeRequest(r *http.Request, scope ...[]string) (oauth.Context, error) {
	var claims jwt.MapClaims
	var err error
	var aud *oauth.Audience

	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

	token, err := jwt.Parse(bearer, func(token *jwt.Token) (interface{}, error) {
		claims = token.Claims.(jwt.MapClaims)

		switch token.Method.(type) {
		case *jwt.SigningMethodHMAC:
			id, ok := claims["aud"].(string)
			if !ok {
				return nil, oauth.ErrAccessDenied
			}
			aud, err = s.ctrl.AudienceGet(id)
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
		return nil, err
	}

	if !token.Valid {
		return nil, oauth.ErrInvalidToken
	}

	if aud == nil {
		id, ok := claims["aud"].(string)
		if !ok {
			return nil, oauth.ErrAccessDenied
		}
		aud, err = s.ctrl.AudienceGet(id)
		if err != nil {
			return nil, err
		}
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
		return nil, oauth.ErrAccessDenied
	}

	c := &authContext{
		aud:   aud,
		token: token,
	}

	if azp, ok := claims["azp"].(string); ok {
		app, err := s.ctrl.ApplicationGet(azp)
		if err != nil {
			return nil, oauth.ErrAccessDenied
		}
		c.app = app
	}

	if sub, ok := claims["sub"].(string); ok && !strings.HasSuffix(sub, "@applications") {
		user, prin, err := s.ctrl.UserGet(c, sub)
		if err != nil {
			return nil, oauth.ErrAccessDenied
		}
		c.user = user
		c.prin = prin
	}

	return c, nil
}

func (s *Server) reqctx(req *oauth.AuthRequest) *authContext {
	aud, err := s.ctrl.AudienceGet(req.ClientID)
	if err != nil {
		s.log.Errorln(err)
	}

	app, err := s.ctrl.ApplicationGet(req.Audience)
	if err != nil {
		s.log.Errorln(err)
	}

	return &authContext{
		aud: aud,
		app: app,
		req: req,
	}
}

func (s *Server) appctx(app *oauth.Application, aud *oauth.Audience, req *oauth.AuthRequest) *authContext {
	return &authContext{
		aud: aud,
		app: app,
		req: req,
	}
}

func (c *authContext) User() *oauth.User {
	return c.user
}

func (c *authContext) Audience() *oauth.Audience {
	return c.aud
}

func (c *authContext) Application() *oauth.Application {
	return c.app
}

func (c *authContext) Principal() interface{} {
	return c.prin
}

func (c *authContext) Token() *jwt.Token {
	return c.token
}

func (c *authContext) Request() *oauth.AuthRequest {
	return c.req
}
