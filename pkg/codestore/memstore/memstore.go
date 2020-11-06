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

// Package memstore provides an in-memory auth.CodeStore implementation
package memstore

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/libatomic/oauth/pkg/oauth"
	"github.com/mr-tron/base58"
)

type (
	memstore struct {
		*cache
	}
)

// New returns a new in-memory code store
func New(defaultExpiration, cleanupInterval time.Duration) oauth.CodeStore {
	return &memstore{
		cache: new(defaultExpiration, cleanupInterval),
	}
}

// AuthCodeCreate creates a new authcode from the request
func (m *memstore) AuthCodeCreate(_ context.Context, authCode *oauth.AuthCode) error {
	code, err := uuid.NewRandom()
	if err != nil {
		return err
	}

	authCode.IssuedAt = time.Now().Unix()
	authCode.Code = base58.Encode(code[:])

	exp := DefaultExpiration

	// set the default expiration
	if authCode.ExpiresAt == 0 {
		authCode.ExpiresAt = time.Now().Add(m.defaultExpiration).Unix()
	} else if authCode.ExpiresAt > 0 {
		exp = time.Duration(authCode.ExpiresAt-time.Now().Unix()) * time.Second
	}

	if err := m.Add(authCode.Code, authCode, exp); err != nil {
		return err
	}

	return nil
}

// AuthCodeGet returns a code from the store
func (m *memstore) AuthCodeGet(_ context.Context, code string) (*oauth.AuthCode, error) {
	authCode, ok := m.Get(code)
	if !ok {
		return nil, oauth.ErrCodeNotFound
	}

	return authCode.(*oauth.AuthCode), nil
}

// CodeDestroy removes a code from the store
func (m *memstore) AuthCodeDestroy(_ context.Context, code string) error {
	m.Delete(code)
	return nil
}
