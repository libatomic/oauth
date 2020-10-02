/*
 * Copyright (C) 2020 Atomic Media Foundation
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file in the root of this
 * workspace for details.
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
					Name: "SessionDestroy",
					Args: litmus.Args{
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
				EndQuery(),
			ExpectedStatus: http.StatusBadRequest,
			ExpectedResponse: `
{
	"message": "something bad"
}`,
		},
		"LogoutInvalidURI": {
			Operations: []litmus.Operation{
				{
					Name: "ApplicationGet",
					Args: litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{
						&oauth.Application{
							RedirectUris: oauth.Permissions{string([]byte{0x7f})},
						}, nil},
				},
			},
			Method: http.MethodGet,
			Path:   "/oauth/logout",
			Query: litmus.BeginQuery().
				Add("client_id", "00000000-0000-0000-0000-000000000000").
				Add("redirect_uri", string([]byte{0x7f})).
				EndQuery(),
			ExpectedStatus: http.StatusBadRequest,
			ExpectedResponse: `
{
	"message": "parse \"\\u007f\": net/url: invalid control character in URL"
}`,
		},
		"LogoutBadURI": {
			Operations: []litmus.Operation{
				{
					Name:    "ApplicationGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testApp, nil},
				},
			},
			Method: http.MethodGet,
			Path:   "/oauth/logout",
			Query: litmus.BeginQuery().
				Add("client_id", "00000000-0000-0000-0000-000000000000").
				Add("redirect_uri", "https://www.google.com").
				EndQuery(),
			ExpectedStatus: http.StatusBadRequest,
			ExpectedResponse: `
{
	"message": "unauthorized redirect uri"
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
					Name: "SessionDestroy",
					Args: litmus.Args{
						mock.AnythingOfTypeArgument("*api.responseWriter"),
						mock.AnythingOfType("*http.Request")},
					Returns: litmus.Returns{errors.New("bad stuff")},
				},
			},
			Method: http.MethodGet,
			Path:   "/oauth/logout",
			Query: litmus.BeginQuery().
				Add("client_id", "00000000-0000-0000-0000-000000000000").
				EndQuery(),
			ExpectedStatus: http.StatusFound,
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/\?error=server_error&error_description=bad\+stuff`,
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := new(mockController)

			mockServer := New(ctrl, ctrl, api.WithLog(log.Log))

			test.Do(&ctrl.Mock, mockServer, t)
		})
	}
}
