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

// Package server provides an http oauth REST API
package server

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"path/filepath"
	"sync"
	"time"

	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/oauth/pkg/codestore/memstore"
	"github.com/libatomic/oauth/pkg/oauth"
	"github.com/libatomic/oauth/pkg/sessions/cookiestore"
)

type (
	// Server is an API server it can be used standalone vi Server() or integrared via Handler()
	Server struct {
		*api.Server

		ctrl oauth.Controller

		codes oauth.CodeStore

		sessions oauth.SessionStore

		auth oauth.Authorizer

		allowedGrants oauth.Permissions

		allowUnsignedTokens bool

		sessionKey [64]byte

		jwks []byte
	}

	// Option provides the server options, these will override th defaults and instance values.
	Option func(s *Server)

	route struct {
		Path        string
		Method      string
		Params      interface{}
		Handler     interface{}
		Auth        oauth.Permissions
		AuthOptions []oauth.AuthOption
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
func New(ctrl oauth.Controller, opts ...interface{}) *Server {
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

	apiOpts = append(apiOpts, api.WithBasepath("/oauth"))

	s := &Server{
		Server: api.NewServer(apiOpts...),
		ctrl:   ctrl,
		allowedGrants: oauth.Permissions{
			oauth.GrantTypeAuthCode,
			oauth.GrantTypeClientCredentials,
			oauth.GrantTypeRefreshToken,
		},
	}

	// apply the server options
	for _, o := range srvOpts {
		o(s)
	}

	if s.codes == nil {
		s.codes = memstore.New(time.Minute*5, time.Minute*10)
	}

	if s.sessions == nil {
		s.Log().Warn("using insecure cookie store")
		s.sessions = cookiestore.New()
	}

	for _, r := range routes {
		s.addRoute(r)
	}

	return s
}

// WithCodeStore changes the default code store for the server
func WithCodeStore(c oauth.CodeStore) Option {
	return func(s *Server) {
		s.codes = c
	}
}

// WithSessionStore changes the default session store for the server
func WithSessionStore(c oauth.SessionStore) Option {
	return func(s *Server) {
		s.sessions = c
	}
}

// WithAllowedGrants sets allowed grants
func WithAllowedGrants(g oauth.Permissions) Option {
	return func(s *Server) {
		s.allowedGrants = g
	}
}

// WithAuthorizer sets the oauth.Authorizer for the necessary calls
func WithAuthorizer(a oauth.Authorizer) Option {
	return func(s *Server) {
		s.auth = a
	}
}

// Sessions returns the sessions
func (s *Server) Sessions() oauth.SessionStore {
	return s.sessions
}

func (s *Server) addRoute(r route) {
	if len(r.Auth) > 0 {
		if s.auth == nil {
			return
		}

		authOptions := make([]oauth.AuthOption, 0)

		authOptions = append(authOptions, oauth.WithScope(r.Auth))

		if r.AuthOptions != nil {
			authOptions = append(authOptions, r.AuthOptions...)
		}

		s.Server.AddRoute(
			r.Path,
			r.Handler,
			api.WithMethod(r.Method),
			api.WithParams(r.Params),
			api.WithContextFunc(s.addContext),
			api.WithAuthorizers(s.auth.Authorize(authOptions...)),
			api.WithValidation(true),
		)

	} else {
		s.Server.AddRoute(
			r.Path,
			r.Handler,
			api.WithMethod(r.Method),
			api.WithParams(r.Params),
			api.WithContextFunc(s.addContext),
			api.WithValidation(true),
		)
	}
}

func (s *Server) addContext(ctx context.Context) context.Context {
	ctx = context.WithValue(ctx, ctrlKey, s)

	return oauth.NewContext(ctx, s.ctrl)
}

func codeStore(ctx context.Context) oauth.CodeStore {
	s := ctx.Value(ctrlKey).(*Server)
	return s.codes
}

func sessionStore(ctx context.Context) oauth.SessionStore {
	s := ctx.Value(ctrlKey).(*Server)
	return s.sessions
}

func serverContext(ctx context.Context) *Server {
	return ctx.Value(ctrlKey).(*Server)
}

// EnsureURI checks that a uri matches within a list
func EnsureURI(uri string, search []string, r ...*http.Request) (*url.URL, error) {
	if search == nil || len(search) == 0 {
		return nil, errors.New("unauthorized uri")
	}

	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 && r[0].Host == u.Host {
		u.Host = ""
		u.Scheme = ""
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

func registerRoutes(r []route) {
	routeLock.Lock()

	defer routeLock.Unlock()

	routes = append(routes, r...)
}
