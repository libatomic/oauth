package cookiestore

import (
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
	return s.s.Save(nil, w)
}

// Destroy clears the session from the response
func (s *session) Destroy(w http.ResponseWriter) error {
	copy := *s.s
	copy.Options.MaxAge = -1
	copy.Values = make(map[interface{}]interface{})
	return copy.Save(nil, w)
}
