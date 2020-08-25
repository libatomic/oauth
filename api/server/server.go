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
	"encoding/gob"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/oauth/api/server/auth"
	"github.com/libatomic/oauth/api/server/user"
	"github.com/libatomic/oauth/pkg/codestore/memstore"
	"github.com/libatomic/oauth/pkg/oauth"
)

type (
	// Server is an API server it can be used standalone vi Server() or integrared via Handler()
	Server struct {
		*api.Server

		// ctrl is the auth.Controller interface the server uses to complete requests
		ctrl oauth.Controller

		// codes is the authcode store for the server
		codes oauth.CodeStore

		auth oauth.Authorizer

		hash  []byte
		block []byte

		sessionCookie      string
		sessionLifetime    time.Duration
		sessionTimeout     time.Duration
		jwks               []byte
		allowSignup        bool
		allowPasswordGrant bool

		// cookie manages secure cookies
		cookie *securecookie.SecureCookie

		// session is the store for the sessions
		sessions sessions.Store
	}

	// Option provides the server options, these will override th defaults and instance values.
	Option func(s *Server)
)

func init() {
	// register the session type so the store can encode/decode it
	gob.Register(oauth.Session{})
	gob.Register(sessionToken{})
}

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

	apiOpts = append(apiOpts, api.Basepath(SpecDoc.Spec().BasePath))

	const (
		defaultSessionLifetime = time.Duration(time.Hour * 24 * 30)
		defaultSessionTimeout  = time.Duration(time.Hour * 24 * 3)
		defaultSessionCookie   = "_atomic_session"
	)

	var (
		defaultHash  = []byte("40taMVGESjzOvpYx3FvskNYN7r1AtM9M")
		defaultBlock = []byte("seX4pGzKmw0MS0arKYIvoGZAecOR58UP")
	)

	s := &Server{
		Server:          api.NewServer(apiOpts...),
		auth:            athr,
		ctrl:            ctrl,
		sessionCookie:   defaultSessionCookie,
		sessionLifetime: defaultSessionLifetime,
		sessionTimeout:  defaultSessionTimeout,
		codes:           memstore.New(time.Minute*5, time.Minute*10),
		hash:            defaultHash,
		block:           defaultBlock,
	}

	// apply the server options
	for _, o := range srvOpts {
		o(s)
	}

	if s.sessions == nil {
		store := sessions.NewCookieStore(s.hash[0:32], s.block[0:32])

		store.Options = &sessions.Options{
			Secure:   true,
			MaxAge:   int(s.sessionLifetime / time.Second),
			HttpOnly: true,
			Path:     "/",
		}

		s.sessions = store
	}

	// we use this to generate secure values
	s.cookie = securecookie.New(s.hash[0:32], s.block[0:32])

	// setup all of the routes
	s.AddRoute("/authorize", http.MethodGet, &auth.AuthorizeParams{}, s.authorize)

	s.AddRoute("/login", http.MethodPost, &auth.LoginParams{}, s.login)

	s.AddRoute("/signup", http.MethodPost, &auth.SignupParams{}, s.signup)

	s.AddRoute("/token", http.MethodPost, &auth.TokenParams{}, s.token)

	s.AddRoute("/logout", http.MethodGet, &auth.LogoutParams{}, s.logout)

	s.AddRoute("/userInfo", http.MethodGet, &user.UserInfoGetParams{}, s.userInfo, oauth.Scope(oauth.ScopeOpenID, oauth.ScopeProfile))

	s.AddRoute("/userInfo", http.MethodPut, &user.UserInfoUpdateParams{}, s.userInfoUpdate, oauth.Scope(oauth.ScopeOpenID, oauth.ScopeProfile))

	s.AddRoute("/userPrincipal", http.MethodGet, &user.UserPrincipalGetParams{}, s.userPrincipal, oauth.Scope(oauth.ScopeOpenID, oauth.ScopeProfile))

	s.AddRoute("/.well-known/jwks.json", http.MethodGet, &auth.PublicKeyGetParams{}, s.publicKey, oauth.Scope(oauth.ScopeOpenID, oauth.ScopeProfile))

	return s
}

// SessionIntervals sets the session lifetime and activity timeout
func SessionIntervals(lifetime, timeout time.Duration) Option {
	return func(s *Server) {
		if timeout > 0 && lifetime > timeout {
			s.sessionLifetime = lifetime
			s.sessionTimeout = timeout
		}
	}
}

// SessionStore sets the session store
func SessionStore(store sessions.Store) Option {
	return func(s *Server) {
		s.sessions = store
	}
}

// CodeStore sets the code store for the server
func CodeStore(store oauth.CodeStore) Option {
	return func(s *Server) {
		s.codes = store
	}
}

// AllowSignup enables the signup/register paths
func AllowSignup(allow bool) Option {
	return func(s *Server) {
		s.allowSignup = allow
	}
}

// SessionCookieName sets the session cookie name
func SessionCookieName(name string) Option {
	return func(s *Server) {
		s.sessionCookie = name
	}
}

// SessionCookieKeys sets the session cookie keys
func SessionCookieKeys(hash, block []byte) Option {
	return func(s *Server) {
		s.hash = hash
		s.block = block
	}
}

// AllowPasswordGrant enables password grants which require client secrets
func AllowPasswordGrant(allow bool) Option {
	return func(s *Server) {
		s.allowPasswordGrant = allow
	}
}

// AddRoute adds a route using the scopes
func (s *Server) AddRoute(path string, method string, params api.Parameters, handler interface{}, scopes ...oauth.Permissions) {
	if len(scopes) > 0 {
		s.Server.AddRoute(path, method, params, handler, s.auth(scopes...))
	} else {

		s.Server.AddRoute(path, method, params, handler)
	}
}
