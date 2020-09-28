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
	"encoding/gob"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/sessions"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/oauth/api/server/auth"
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
		allowPasswordGrant bool

		// session is the store for the sessions
		sessions sessions.Store
	}

	// Option provides the server options, these will override th defaults and instance values.
	Option func(s *Server)

	sessionToken struct {
		Timeout   int64
		SessionID string
	}

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

	apiOpts = append(apiOpts, api.WithBasepath(SpecDoc.Spec().BasePath))

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

	for _, r := range routes {
		s.addRoute(r.Path, r.Method, r.Params, r.Handler, r.Auth)
	}

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
		if uu.Scheme == u.Scheme && u.Host == uu.Host && u.Path == uu.Path {
			return u, nil
		}
	}

	return nil, errors.New("unauthorized redirect uri")
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

	pubKey, err := s.ctrl.TokenPublicKey(oauth.NewContext(ctx, oauth.WithAudience(aud)))
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
