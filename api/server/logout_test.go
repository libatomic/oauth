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
	"errors"
	"net/http"
	"testing"

	"github.com/apex/log"
	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/litmus/pkg/litmus"
	"github.com/libatomic/oauth/pkg/oauth"
	"github.com/stretchr/testify/mock"
)

func TestLogout(t *testing.T) {
	tests := map[string]litmus.Test{
		"LogoutOK": {
			Operations: []litmus.Operation{
				{
					Name:    "ApplicationGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testApp, nil},
				},
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testAud, nil},
				},
				{
					Name: "SessionDestroy",
					Args: litmus.Args{
						litmus.Context,
						mock.AnythingOfTypeArgument("*api.responseWriter"),
						mock.AnythingOfType("*http.Request")},
					Returns: litmus.Returns{nil},
				},
			},
			Method: http.MethodGet,
			Path:   "/oauth/logout",
			Query: litmus.BeginQuery().
				Add("client_id", "00000000-0000-0000-0000-000000000000").
				Add("state", "foo").
				EndQuery(),
			ExpectedStatus: http.StatusFound,
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/`,
			},
		},
		"LogoutAppFailed": {
			Operations: []litmus.Operation{
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testAud, nil},
				},
				{
					Name:    "ApplicationGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{nil, errors.New("something bad")},
				},
			},
			Method: http.MethodGet,
			Path:   "/oauth/logout",
			Query: litmus.BeginQuery().
				Add("client_id", "00000000-0000-0000-0000-000000000000").
				Add("redirect_uri", mockURI+"?logout").
				Add("audience", testAud.name).
				EndQuery(),
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedResponse: `
{
	"error":"invalid_client", 
	"error_description":"application lookup failed: something bad"
}`,
		},
		"LogoutInvalidURI": {
			Operations: []litmus.Operation{},
			Method:     http.MethodGet,
			Path:       "/oauth/logout",
			Query: litmus.BeginQuery().
				Add("client_id", "00000000-0000-0000-0000-000000000000").
				Add("redirect_uri", string([]byte{0x7f})).
				Add("audience", testAud.name).
				EndQuery(),
			ExpectedStatus: http.StatusBadRequest,
			ExpectedResponse: `
{
	"message": "redirect_uri: must be a valid request URI."
}`,
		},
		"LogoutBadURI": {
			Operations: []litmus.Operation{
				{
					Name:    "ApplicationGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testApp, nil},
				},
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testAud, nil},
				},
			},
			Method: http.MethodGet,
			Path:   "/oauth/logout",
			Query: litmus.BeginQuery().
				Add("client_id", "00000000-0000-0000-0000-000000000000").
				Add("redirect_uri", "https://www.google.com").
				Add("audience", testAud.name).
				EndQuery(),
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedResponse: `
			{
				"error":"access_denied", 
				"error_description":"unauthorized uri"
			}`,
		},
		"LogoutSessionDestroyFail": {
			Operations: []litmus.Operation{
				{
					Name:    "ApplicationGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testApp, nil},
				},
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testAud, nil},
				},
				{
					Name: "SessionDestroy",
					Args: litmus.Args{
						litmus.Context,
						mock.AnythingOfTypeArgument("*api.responseWriter"),
						mock.AnythingOfType("*http.Request")},
					Returns: litmus.Returns{errors.New("bad stuff")},
				},
			},
			Method: http.MethodGet,
			Path:   "/oauth/logout",
			Query: litmus.BeginQuery().
				Add("client_id", "00000000-0000-0000-0000-000000000000").
				Add("audience", testAud.name).
				EndQuery(),
			ExpectedStatus: http.StatusFound,
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/\?error=server_error&error_description=bad\+stuff`,
			},
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

func TestLogoutErrAudNotFound(t *testing.T) {
	test := litmus.Test{
		Operations: []litmus.Operation{
			{
				Name:    "AudienceGet",
				Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
				Returns: litmus.Returns{nil, oauth.ErrAudienceNotFound},
			},
		},
		Method: http.MethodGet,
		Path:   "/oauth/logout",
		Query: litmus.BeginQuery().
			Add("client_id", "00000000-0000-0000-0000-000000000000").
			Add("audience", testAud.name).
			EndQuery(),
		ExpectedStatus: http.StatusBadRequest,
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl))

	test.Do(&ctrl.Mock, mockServer, t)
}
