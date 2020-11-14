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

package cookiestore

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
)

type (
	session struct {
		s *sessions.Session
	}
)

// ID is the session id
func (s *session) ID() string {
	return s.s.ID
}

// ClientID is the client that created the user session
func (s *session) ClientID() string {
	return s.s.Values["client_id"].(string)
}

func (s *session) Audience() string {
	return s.s.Values["aud"].(string)
}

// CreatedAt is the session creation time
func (s *session) CreatedAt() time.Time {
	return time.Unix(s.s.Values["created_at"].(int64), 0)
}

// ExpiresAt is the session expriation time
func (s *session) ExpiresAt() time.Time {
	return time.Unix(s.s.Values["expires_at"].(int64), 0)
}

// Subject is the user subject id
func (s *session) Subject() string {
	return s.s.Values["subject"].(string)
}

// Set sets a value in the session interface
func (s *session) Set(key string, value interface{}) {
	s.s.Values[key] = value
}

// Get gets a value from the session interface
func (s *session) Get(key string) interface{} {
	return s.s.Values[key]
}

// Write writes the session to the response
func (s *session) Write(w http.ResponseWriter) error {

	// write the id cookie here as well
	id := &http.Cookie{
		Name:     fmt.Sprintf("%s#id", s.s.Name()),
		Value:    s.s.ID,
		Expires:  s.ExpiresAt(),
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	}

	http.SetCookie(w, id)

	return s.s.Save(nil, w)
}

// Destroy clears the session from the response
func (s *session) Destroy(w http.ResponseWriter) error {
	id := &http.Cookie{
		Name:     fmt.Sprintf("%s#id", s.s.Name()),
		Value:    "",
		MaxAge:   -1,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	}

	http.SetCookie(w, id)

	copy := *s.s
	copy.Options.MaxAge = -1
	copy.Values = make(map[interface{}]interface{})

	return copy.Save(nil, w)
}
