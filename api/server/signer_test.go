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

package server

import (
	"context"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSignValue(t *testing.T) {
	badKey := *testKey

	badKey.E = 99

	tests := map[string]struct {
		privKey        *rsa.PrivateKey
		key            string
		val            interface{}
		expectedError  error
		expectedResult string
	}{
		"TestSignValueBadValue": {
			privKey:       testKey,
			key:           AuthRequestParam,
			val:           make(chan int),
			expectedError: errors.New("json: unsupported type: chan int"),
		},
		"TestSignValueBadKey": {
			privKey:       &badKey,
			key:           AuthRequestParam,
			val:           struct{}{},
			expectedError: errors.New("rsa: internal error"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			res, err := signValue(context.TODO(), test.privKey, test.key, test.val)

			if test.expectedError != nil {
				if assert.Error(t, err) {
					assert.EqualError(t, err, test.expectedError.Error(), err)
				}
			} else {
				assert.Equal(t, test.expectedResult, res)
			}
		})
	}
}

func TestVerifyValue(t *testing.T) {
	badKey := testKey.PublicKey

	badKey.E = -99

	tests := map[string]struct {
		pubKey         *rsa.PublicKey
		key            string
		val            string
		expectedError  error
		expectedResult string
		out            struct {
			Foo string
		}
	}{
		"TestVerifyBadValue": {
			pubKey:        &testKey.PublicKey,
			key:           AuthRequestParam,
			val:           "foo.bar/x0329",
			expectedError: errors.New("illegal base64 data at input byte 3"),
		},
		"TestVerifyBadKey": {
			pubKey:        &badKey,
			key:           AuthRequestParam,
			val:           "foo.bar",
			expectedError: errors.New("crypto/rsa: verification error"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := verifyValue(context.TODO(), test.pubKey, test.key, test.val, &test.out)
			if assert.Error(t, err) {
				assert.EqualError(t, err, test.expectedError.Error(), err)
			}
		})
	}
}
