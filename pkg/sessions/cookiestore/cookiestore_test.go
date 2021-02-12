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
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStore(t *testing.T) {
	store := New()

	r := httptest.NewRequest(http.MethodGet, "/foo", nil)
	w := httptest.NewRecorder()

	sess, err := store.SessionCreate(context.TODO(), r)
	assert.Nil(t, err, "failed to create the session")

	err = sess.Write(w)

	r.Header["Cookie"] = w.Header()["Set-Cookie"]

	assert.Nil(t, err, "failed to write the session")

	sess, err = store.SessionRead(context.TODO(), r)

	assert.Nil(t, err, "failed to read the session")

	err = store.SessionDestroy(context.TODO(), w, r)

	assert.Nil(t, err, "failed to destroy the session")
}
