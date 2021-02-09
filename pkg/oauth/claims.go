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

// Package oauth provides the base auth interfaces
package oauth

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"strings"
	"time"

	"errors"

	"github.com/dgrijalva/jwt-go"
)

type (
	// Claims is token claims
	Claims map[string]interface{}
)

// Set sets a value in the claims
func (c Claims) Set(key string, value interface{}) {
	c[key] = value
}

// ID returns the token id
func (c Claims) ID() string {
	if s, ok := c["jti"].(string); ok {
		return s
	}

	return ""
}

// Subject returns the subject for the token
func (c Claims) Subject() string {
	if s, ok := c["sub"].(string); ok {
		return s
	} else if s, ok := c["subject"].(*string); ok {
		return *s
	}

	return ""
}

// Scope returns the scope for the token
func (c Claims) Scope() Permissions {
	switch t := c["scope"].(type) {
	case string:
		return Permissions(strings.Fields(t))
	case []string:
		return Permissions(t)
	case Permissions:
		return t
	}

	return make(Permissions, 0)
}

// Audience returns the audience for the token
func (c Claims) Audience() []string {
	switch s := c["aud"].(type) {
	case string:
		return []string{s}
	case []string:
		return s
	}

	return []string{}
}

// ClientID returns the client (application) id for the token
func (c Claims) ClientID() string {
	if s, ok := c["azp"].(string); ok {
		return s
	} else if s, ok := c["client_id"].(string); ok {
		return s
	}

	return ""
}

// Use returns the token use
func (c Claims) Use() string {
	if s, ok := c["use"].(string); ok {
		return s
	}

	return ""
}

// IssuedAt returns the issue time for the token
func (c Claims) IssuedAt() time.Time {
	if s, ok := c["iat"].(int64); ok {
		return time.Unix(s, 0)
	}

	return time.Time{}
}

// ExpiresAt returns the expiration for the token
func (c Claims) ExpiresAt() time.Time {
	if s, ok := c["exp"].(int64); ok {
		return time.Unix(s, 0)
	}

	return time.Time{}
}

// Valid validates the claims
func (c Claims) Valid() error {
	return jwt.MapClaims(c).Valid()
}

// Sign returns the signed jwt bearer token
func (c Claims) Sign(ctx context.Context, alg string, key interface{}) (string, error) {
	var token *jwt.Token

	switch alg {
	case "RS256":
		token = jwt.NewWithClaims(jwt.SigningMethodRS256, c)

	case "HS256":
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, c)

	}
	return token.SignedString(key)
}

// Value returns Map as a value that can be stored as json in the database
func (c Claims) Value() (driver.Value, error) {
	return json.Marshal(c)
}

// Scan reads a json value from the database into a Map
func (c Claims) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}

	if err := json.Unmarshal(b, &c); err != nil {
		return err
	}

	return nil
}

// ParseClaims parses the jwt token into claims
func ParseClaims(ctx context.Context, bearer string, keyfn func(claims Claims) (interface{}, error)) (Claims, error) {
	token, err := jwt.ParseWithClaims(bearer, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return keyfn(*token.Claims.(*Claims))
	})
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	return *token.Claims.(*Claims), nil
}
