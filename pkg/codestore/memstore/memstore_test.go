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
	"testing"
	"time"

	"github.com/libatomic/oauth/pkg/oauth"
	"github.com/stretchr/testify/assert"
)

func TestAuthCode(t *testing.T) {
	store := New(time.Hour, time.Hour)

	assert.NotNil(t, store, "failed to create memstore")

	code := &oauth.AuthCode{}

	err := store.AuthCodeCreate(context.TODO(), code)

	assert.NoError(t, err, "failed to create authcode")

	rcode, err := store.AuthCodeGet(context.TODO(), code.Code)

	assert.NoError(t, err, "failed to get authcode")

	assert.NotNil(t, rcode, "invalid code returned")

	err = store.AuthCodeDestroy(context.TODO(), code.Code)

	assert.NoError(t, err, "failed to get authcode")
}
