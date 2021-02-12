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

// Package cookiestore provides a cookie based session storage
package cookiestore

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/libatomic/oauth/pkg/oauth"
	"github.com/mr-tron/base58"
)

type (
	cookieStore struct {
		store           *sessions.CookieStore
		sessionCookie   string
		sessionLifetime time.Duration
		sessionTimeout  time.Duration
		hash            []byte
		block           []byte
		multiAudience   bool
	}

	// Option is an option for cookie store options
	Option func(c *cookieStore)
)

var (
	defaultHash  = []byte("40taMVGESjzOvpYx3FvskNYN7r1AtM9M")
	defaultBlock = []byte("seX4pGzKmw0MS0arKYIvoGZAecOR58UP")
)

// New returns a new cookie based session store
func New(opts ...Option) oauth.SessionStore {
	const (
		defaultSessionLifetime = time.Duration(time.Hour * 24 * 30)
		defaultSessionTimeout  = time.Duration(time.Hour * 24 * 3)
		defaultSessionCookie   = "_atomic_session"
	)

	s := &cookieStore{
		sessionLifetime: defaultSessionLifetime,
		sessionTimeout:  defaultSessionTimeout,
		sessionCookie:   defaultSessionCookie,
		hash:            defaultHash,
		block:           defaultBlock,
	}

	for _, opt := range opts {
		opt(s)
	}

	s.store = sessions.NewCookieStore(s.hash[0:32], s.block[0:32])

	s.store.Options = &sessions.Options{
		Secure:   true,
		MaxAge:   int(s.sessionLifetime / time.Second),
		HttpOnly: true,
		Path:     "/",
	}

	return s
}

// WithTimeout sets the store session activity timeout
func WithTimeout(timeout time.Duration) Option {
	return func(c *cookieStore) {
		c.sessionTimeout = timeout
	}
}

// WithLifetime sets the store session lifetime
func WithLifetime(lifetime time.Duration) Option {
	return func(c *cookieStore) {
		c.sessionLifetime = lifetime
	}
}

// WithCookieName sets the session cookie name
func WithCookieName(name string) Option {
	return func(c *cookieStore) {
		c.sessionCookie = name
	}
}

// WithSessionKey sets the session cookie keys
func WithSessionKey(key [64]byte) Option {
	return func(c *cookieStore) {
		c.hash = key[0:32]
		c.block = key[32:64]
	}
}

// WithMultiAudience will not restrict the session cookies to a single audience
func WithMultiAudience(m bool) Option {
	return func(c *cookieStore) {
		c.multiAudience = m
	}
}

// SessionCreate creates a session
func (c *cookieStore) SessionCreate(ctx context.Context, r *http.Request) (oauth.Session, error) {
	octx := oauth.AuthContext(ctx)

	name := c.sessionCookie

	if octx.Audience != nil && !c.multiAudience {
		name = fmt.Sprintf("%s#%s", c.sessionCookie, octx.Audience.Name())
	}

	s, err := c.store.New(r, name)
	if err != nil {
		return nil, err
	}

	if s.IsNew || s.ID == "" {
		uid := uuid.Must(uuid.NewRandom())
		s.ID = base58.Encode(uid[:])
	}

	if octx.Application != nil {
		s.Values["client_id"] = octx.Application.ClientID
	}

	if octx.User != nil {
		s.Values["subject"] = octx.User.Profile.Subject
	}

	if octx.Audience != nil {
		s.Values["aud"] = octx.Audience.Name()
	}

	s.Values["created_at"] = time.Now().Unix()
	s.Values["expires_at"] = time.Now().Add(c.sessionLifetime).Unix()

	s.Options.MaxAge = int(c.sessionTimeout / time.Second)

	return &session{s}, nil
}

// SessionRead returns the session
func (c *cookieStore) SessionRead(ctx context.Context, r *http.Request) (oauth.Session, error) {
	octx := oauth.AuthContext(ctx)

	name := c.sessionCookie

	if octx.Audience != nil && !c.multiAudience {
		name = fmt.Sprintf("%s#%s", c.sessionCookie, octx.Audience.Name())
	}

	s, err := c.store.Get(r, name)
	if err != nil {
		return nil, err
	}

	if _, ok := s.Values["created_at"]; !ok {
		return nil, oauth.ErrSessionNotFound
	}

	s.Options.MaxAge = int(c.sessionTimeout / time.Second)

	return &session{s}, nil
}

func (c *cookieStore) SessionDestroy(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	s, err := c.SessionRead(ctx, r)
	if err != nil {
		return err
	}

	return s.Destroy(w)
}
