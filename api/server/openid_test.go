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
	"net/http"
	"testing"

	"github.com/apex/log"
	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/litmus/pkg/litmus"
	"github.com/libatomic/oauth/pkg/oauth"
	"github.com/stretchr/testify/mock"
)

func TestOpenIDConfig(t *testing.T) {
	tests := map[string]litmus.Test{
		"OpenIDConfig": {
			Operations: []litmus.Operation{
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testAud, nil},
				},
			},
			Method:         http.MethodGet,
			Path:           "/oauth/.well-known/openid-configuration",
			ExpectedStatus: http.StatusOK,
		},
		"OpenIDConfigError": {
			Operations: []litmus.Operation{
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{nil, oauth.ErrAudienceNotFound},
				},
			},
			Method:         http.MethodGet,
			Path:           "/oauth/.well-known/openid-configuration",
			ExpectedStatus: http.StatusBadRequest,
			ExpectedResponse: `
			{
				"error":"invalid_request", 
				"error_description":"audience lookup failed: audience not found"
			}`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := new(MockController)

			mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl))

			test.Do(&ctrl.Mock, mockServer, t)
		})
	}
}

func TestJWKS(t *testing.T) {
	tests := map[string]litmus.Test{
		"JWKS": {
			Operations: []litmus.Operation{
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testAud, nil},
				},
			},
			Method:         http.MethodGet,
			Path:           "/oauth/.well-known/jwks.json",
			ExpectedStatus: http.StatusOK,
		},
		"JWKSBadAudience": {
			Operations: []litmus.Operation{
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{nil, oauth.ErrAudienceNotFound},
				},
			},
			Method:         http.MethodGet,
			Path:           "/oauth/.well-known/jwks.json",
			ExpectedStatus: http.StatusBadRequest,
			ExpectedResponse: `
			{
				"error":"invalid_request", 
				"error_description":"audience lookup failed: audience not found"
			}`,
		},
		"JWKSBadAlgorithm": {
			Operations: []litmus.Operation{
				{
					Name: "AudienceGet",
					Args: litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{&mockAudience{
						tokenAlgorithm: oauth.AudienceTokenAlgorithmHS256,
					}, nil},
				},
			},
			Method:         http.MethodGet,
			Path:           "/oauth/.well-known/jwks.json",
			ExpectedStatus: http.StatusBadRequest,
			ExpectedResponse: `
			{
				"error":"invalid_request", 
				"error_description":"audience does not support rsa tokens"
			}`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := new(MockController)

			mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl))

			test.Do(&ctrl.Mock, mockServer, t)
		})
	}
}
