/*
 * Copyright (C) 2020 Atomic Media Foundation
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file in the root of this
 * workspace for details.
 */

// Package rest provides an http oauth REST API
package rest

import (
	"context"
	"crypto/rsa"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/libatomic/oauth/pkg/codestore/memstore"
	"github.com/libatomic/oauth/pkg/oauth"
	"github.com/sirupsen/logrus"
)

type (
	// Server is an API server it can be used standalone vi Server() or integrared via Handler()
	Server struct {
		// ctrl is the auth.Controller interface the server uses to complete requests
		ctrl oauth.Controller

		// codes is the authcode store for the server
		codes oauth.CodeStore

		// signingKey is used to sign tokens, session cookies, and request values to ensure they are passed
		// securely from the browser. The public key is used to verify requests back from the
		// browser. If it is not configured cookies and tokens will be unsigned.
		signingKey *rsa.PrivateKey

		sessionCookie   string
		sessionLifetime time.Duration
		sessionTimeout  time.Duration
		log             *logrus.Logger
		router          *mux.Router
		apiRouter       *mux.Router
		addr            string
		srv             *http.Server
		lock            sync.Mutex
		jwks            []byte
		allowSignup     bool
		basePath        string

		// cookie manages secure cookies
		cookie *securecookie.SecureCookie

		// session is the store for the sessions
		sessions sessions.Store
	}

	// Option provides the server options, these will override th defaults and instance values.
	Option func(*Server)
)

func init() {
	// register the session type so the store can encode/decode it
	gob.Register(oauth.Session{})
	gob.Register(sessionToken{})
}

// New returns a new Server instance
func New(ctrl oauth.Controller, signingKey *rsa.PrivateKey, opts ...Option) *Server {
	const (
		defaultSessionLifetime = time.Duration(time.Hour * 24 * 30)
		defaultSessionTimeout  = time.Duration(time.Hour * 24 * 3)
		defaultAddr            = "127.0.0.1:9000"
	)

	s := &Server{
		ctrl:            ctrl,
		signingKey:      signingKey,
		sessionCookie:   SessionCookie,
		sessionLifetime: defaultSessionLifetime,
		sessionTimeout:  defaultSessionTimeout,
		log:             logrus.StandardLogger(),
		router:          mux.NewRouter(),
		addr:            defaultAddr,
		codes:           memstore.New(time.Minute*5, time.Minute*10),
		basePath:        SpecDoc.BasePath(),
	}

	// use the public key for hashing
	hash := signingKey.PublicKey.N.Bytes()

	// use the private key for encryption
	block := signingKey.D.Bytes()

	for _, opt := range opts {
		opt(s)
	}

	if s.sessions == nil {
		store := sessions.NewCookieStore(hash[0:32], block[0:32])

		store.Options = &sessions.Options{
			Secure:   true,
			MaxAge:   int(s.sessionLifetime / time.Second),
			HttpOnly: true,
			Path:     "/",
		}

		s.sessions = store
	}

	for _, opt := range opts {
		opt(s)
	}

	// we use this to generate secure values
	s.cookie = securecookie.New(hash[0:32], block[0:32])

	s.apiRouter = s.router.PathPrefix(s.basePath).Subrouter()
	s.apiRouter.Use(versionMiddleware)

	// setup all of the routes
	s.apiRouter.HandleFunc("/authorize", s.authorize).Methods(http.MethodGet)

	s.apiRouter.HandleFunc("/login", s.login).Methods(http.MethodPost)

	s.apiRouter.HandleFunc("/signup", s.signup).Methods(http.MethodPost)

	s.apiRouter.HandleFunc("/token", s.token).Methods(http.MethodPost)

	s.apiRouter.HandleFunc("/logout", s.logout).Methods(http.MethodGet)

	s.apiRouter.HandleFunc("/userInfo", s.userInfo).Methods(http.MethodGet)

	s.apiRouter.HandleFunc("/.well-known/jwks.json", s.publicKey).Methods(http.MethodGet)

	return s
}

// WithSessionIntervals sets the session lifetime and activity timeout
func WithSessionIntervals(lifetime, timeout time.Duration) Option {
	return func(s *Server) {
		if timeout > 0 && lifetime > timeout {
			s.sessionLifetime = lifetime
			s.sessionTimeout = timeout
		}
	}
}

// WithLogger specifies a new logger
func WithLogger(logger *logrus.Logger) Option {
	return func(s *Server) {
		if logger != nil {
			s.log = logger
		}
	}
}

// WithRouter specifies the router to use
func WithRouter(router *mux.Router) Option {
	return func(s *Server) {
		if router != nil {
			s.router = router
		}
	}
}

// WithAddr sets the listen address for the server
func WithAddr(addr string) Option {
	return func(s *Server) {
		if addr != "" {
			s.addr = addr
		}
	}
}

// WithSessionStore sets the session store
func WithSessionStore(store sessions.Store) Option {
	return func(s *Server) {
		s.sessions = store
	}
}

// WithCodeStore sets the code store for the server
func WithCodeStore(store oauth.CodeStore) Option {
	return func(s *Server) {
		s.codes = store
	}
}

// WithBasepath sets the server basepath
func WithBasepath(basePath string) Option {
	return func(s *Server) {
		s.basePath = basePath
	}
}

// WithAllowSignup enables the signup/register paths
func WithAllowSignup(allow bool) Option {
	return func(s *Server) {
		s.allowSignup = allow
	}
}

// Serve starts the http server
func (s *Server) Serve() error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.srv != nil {
		return errors.New("server already running")
	}

	s.srv = &http.Server{
		Addr:    s.addr,
		Handler: s.router,
	}

	go func() {
		if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.log.Fatalf("listen: %s\n", err)
		}
	}()

	s.log.Debugf("http server listening on: %s", s.addr)

	return nil
}

// Shutdown shuts down the http server with the context
func (s *Server) Shutdown(ctx context.Context) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.srv == nil {
		s.log.Fatal("server already shutdown")
	}

	err := s.srv.Shutdown(ctx)

	s.srv = nil

	return err
}

// Router returns the server router
func (s *Server) Router() *mux.Router {
	return s.router
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, v interface{}, pretty ...bool) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)

	if len(pretty) > 0 && pretty[0] {
		enc.SetIndent("", "\t")
	}

	if err := enc.Encode(v); err != nil {
		s.log.Errorln(err)
	}
}

func (s *Server) writeError(w http.ResponseWriter, status int, format string, args ...interface{}) {
	err := oauth.ErrorResponse{
		Message: fmt.Sprintf(format, args...),
	}

	s.writeJSON(w, status, err)
}

func (s *Server) writeErr(w http.ResponseWriter, status int, err error) {
	s.writeError(w, status, err.Error())
}

func (s *Server) redirectError(w http.ResponseWriter, u *url.URL, args map[string]string) {
	q := u.Query()

	for k, v := range args {
		q.Set(k, v)
	}

	u.RawQuery = q.Encode()

	w.Header().Set("Location", u.String())
	w.WriteHeader(http.StatusFound)
}
