/*
 * Copyright (C) 2020 Atomic Media Foundation
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file in the root of this
 * workspace for details.
 */

// Package server provides an http oauth REST API
package server

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"path/filepath"
	"sync"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/oauth/api/server/auth"
	"github.com/libatomic/oauth/pkg/oauth"
)

type (
	// Server is an API server it can be used standalone vi Server() or integrared via Handler()
	Server struct {
		*api.Server

		// ctrl is the auth.Controller interface the server uses to complete requests
		ctrl oauth.Controller

		auth oauth.Authorizer

		jwks []byte
	}

	// Option provides the server options, these will override th defaults and instance values.
	Option func(s *Server)

	route struct {
		Path    string
		Method  string
		Params  api.Parameters
		Handler interface{}
		Auth    oauth.Permissions
	}

	contextKey string
)

const (
	// AuthRequestParam is the name of the request token parameter
	AuthRequestParam = "request_token"
)

var (
	routes = make([]route, 0)

	routeLock sync.Mutex

	ctrlKey contextKey = "oauth.Controller"
)

// New returns a new Server instance
func New(ctrl oauth.Controller, athr oauth.Authorizer, opts ...interface{}) *Server {
	apiOpts := make([]api.Option, 0)
	srvOpts := make([]Option, 0)

	for _, o := range opts {
		switch opt := o.(type) {
		case api.Option:
			apiOpts = append(apiOpts, opt)

		case Option:
			srvOpts = append(srvOpts, opt)
		}

	}

	apiOpts = append(apiOpts, api.WithBasepath(SpecDoc.Spec().BasePath))

	s := &Server{
		Server: api.NewServer(apiOpts...),
		auth:   athr,
		ctrl:   ctrl,
	}

	// apply the server options
	for _, o := range srvOpts {
		o(s)
	}

	for _, r := range routes {
		s.addRoute(r.Path, r.Method, r.Params, r.Handler, r.Auth)
	}

	s.addRoute(
		"/.well-known/jwks.json",
		http.MethodGet,
		&auth.PublicKeyGetParams{},
		s.publicKey,
		oauth.Scope(oauth.ScopeOpenID, oauth.ScopeProfile))

	return s
}

func (s *Server) addRoute(path string, method string, params api.Parameters, handler interface{}, scopes ...oauth.Permissions) {
	if len(scopes) > 0 && scopes[0] != nil {
		s.Server.AddRoute(path, method, params, handler, s.addContext, s.auth.Authorize(oauth.WithScope(scopes...)))
	} else {
		s.Server.AddRoute(path, method, params, handler, s.addContext)
	}
}

func (s *Server) addContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctrlKey, s.ctrl)
}

func getController(ctx context.Context) oauth.Controller {
	return ctx.Value(ctrlKey).(oauth.Controller)
}

func ensureURI(uri string, search []string) (*url.URL, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	for _, a := range search {
		if a == u.String() {
			return u, nil
		}

		uu, _ := url.Parse(a)
		if uu.Scheme == u.Scheme && u.Host == uu.Host {
			if ok, _ := filepath.Match(uu.Path, u.Path); ok {
				return u, nil
			}
		}
	}

	return nil, errors.New("unauthorized uri")
}

func (s *Server) publicKey(ctx context.Context, params *auth.PublicKeyGetParams) api.Responder {
	var aud *oauth.Audience
	var err error

	if params.Audience != nil {
		aud, err = s.ctrl.AudienceGet(ctx, *params.Audience)
		if err != nil {
			return api.StatusError(http.StatusBadRequest, err)
		}
	}

	pubKey, err := s.ctrl.TokenPublicKey(oauth.NewContext(ctx, oauth.Context{Audience: aud}))
	if err != nil {
		return api.StatusError(http.StatusInternalServerError, err)
	}

	// create the jwks output
	key, err := jwk.New(pubKey)
	if err != nil {
		return api.StatusError(http.StatusInternalServerError, err)

	}

	thumb, err := key.Thumbprint(crypto.SHA1)
	if err != nil {
		return api.StatusError(http.StatusInternalServerError, err)

	}

	// usw the thumbprint as kid and x5t
	key.Set("kid", hex.EncodeToString(thumb))
	key.Set("x5t", base64.RawURLEncoding.EncodeToString(thumb))

	key.Set("alg", "RS256")
	key.Set("use", "sig")

	keys := map[string]interface{}{
		"keys": []interface{}{key},
	}

	return api.NewResponse(keys)
}

func registerRoutes(r []route) {
	routeLock.Lock()

	defer routeLock.Unlock()

	routes = append(routes, r...)
}
