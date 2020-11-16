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
	"strings"
	"time"

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

// Subject returns the subject for the token
func (c Claims) Subject() string {
	if s, ok := c["sub"].(string); ok {
		return s
	}

	return ""
}

// Scope returns the scope for the token
func (c Claims) Scope() Permissions {
	if s, ok := c["scope"].(string); ok {
		return Permissions(strings.Fields(s))
	}

	return make(Permissions, 0)
}

// Audience returns the audience for the token
func (c Claims) Audience() string {
	if s, ok := c["aud"].(string); ok {
		return s
	}

	return ""
}

// ClientID returns the client (application) id for the token
func (c Claims) ClientID() string {
	if s, ok := c["azp"].(string); ok {
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

// ParseClaims parses the jwt token into claims
func ParseClaims(ctx context.Context, bearer string, key interface{}) (Claims, error) {
	token, err := jwt.Parse(bearer, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	return Claims(token.Claims.(jwt.MapClaims)), nil
}