/*
 * Copyright (C) 2020 Atomic Media Foundation
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file in the root of this
 * workspace for details.
 */

// Package memstore provides an in-memory auth.CodeStore implementation
package memstore

import (
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
func (m *memstore) AuthCodeCreate(_ oauth.Context, authCode *oauth.AuthCode) error {
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
func (m *memstore) AuthCodeGet(_ oauth.Context, code string) (*oauth.AuthCode, error) {
	authCode, ok := m.Get(code)
	if !ok {
		return nil, oauth.ErrCodeNotFound
	}

	return authCode.(*oauth.AuthCode), nil
}

// CodeDestroy removes a code from the store
func (m *memstore) AuthCodeDestroy(_ oauth.Context, code string) error {
	m.Delete(code)
	return nil
}
