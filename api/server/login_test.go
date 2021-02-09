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
	"github.com/fatih/structs"
	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/litmus/pkg/litmus"
	"github.com/libatomic/oauth/pkg/oauth"
	"github.com/stretchr/testify/mock"
)

func TestLogin(t *testing.T) {
	tests := map[string]litmus.Test{
		"LoginOK": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenValidate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{oauth.Claims(structs.Map(testRequest)), nil},
				},
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testAud, nil},
				},
				{
					Name:    "ApplicationGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testApp, nil},
				},
				{
					Name:    "UserAuthenticate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string"), mock.AnythingOfType("string")},
					Returns: litmus.Returns{testUser, testPrin, nil},
				},
				{
					Name:    "SessionCreate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("*http.Request")},
					Returns: litmus.Returns{testSession, nil},
				},
				{
					Name:    "AuthCodeCreate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("*oauth.AuthCode")},
					Returns: litmus.Returns{nil},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/login",
			ExpectedStatus:     http.StatusFound,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("login", "hiro@metaverse.org").
				Add("password", "password").
				Add("request_token", testToken).
				Encode(),
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/\?code=00000000-0000-0000-0000-000000000000`,
			},
		},
		"LoginOKEmptyScope": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenValidate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{oauth.Claims(structs.Map(testRequest)), nil},
				},
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testAud, nil},
				},
				{
					Name:    "ApplicationGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testApp, nil},
				},
				{
					Name:    "UserAuthenticate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string"), mock.AnythingOfType("string")},
					Returns: litmus.Returns{testUser, testPrin, nil},
				},
				{
					Name:    "SessionCreate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("*http.Request")},
					Returns: litmus.Returns{testSession, nil},
				},
				{
					Name:    "AuthCodeCreate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("*oauth.AuthCode")},
					Returns: litmus.Returns{nil},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/login",
			ExpectedStatus:     http.StatusFound,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("login", "hiro@metaverse.org").
				Add("password", "password").
				Add("request_token", emptyScopeToken).
				Encode(),
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/\?code=00000000-0000-0000-0000-000000000000`,
			},
		},
		"LoginBadToken": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenValidate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{oauth.Claims{}, errors.New("bad token")},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/login",
			ExpectedStatus:     http.StatusBadRequest,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("login", "hiro@metaverse.org").
				Add("password", "password").
				Add("request_token", "bad-token").
				Encode(),
			ExpectedResponse: `
{
	"message": "bad token"
}`,
		},
		"LoginExpiredToken": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenValidate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{oauth.Claims(structs.Map(expiredReq)), nil},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/login",
			ExpectedStatus:     http.StatusFound,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("login", "hiro@metaverse.org").
				Add("password", "password").
				Add("request_token", expiredToken).
				Encode(),
		},
		"LoginContextError": {
			Operations: []litmus.Operation{
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{nil, errors.New("bad stuff")},
				},
				{
					Name:    "TokenValidate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{oauth.Claims(structs.Map(testRequest)), nil},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/login",
			ExpectedStatus:     http.StatusFound,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("login", "hiro@metaverse.org").
				Add("password", "password").
				Add("request_token", testToken).
				Encode(),
		},
		"LoginAuthFail": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenValidate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{oauth.Claims(structs.Map(testRequest)), nil},
				},
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testAud, nil},
				},
				{
					Name:    "ApplicationGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testApp, nil},
				},
				{
					Name:    "UserAuthenticate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string"), mock.AnythingOfType("string")},
					Returns: litmus.Returns{nil, nil, oauth.ErrAccessDenied},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/login",
			ExpectedStatus:     http.StatusFound,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("login", "hiro@metaverse.org").
				Add("password", "password").
				Add("request_token", testToken).
				Encode(),
		},
		"LoginUserAudMissing": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenValidate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{oauth.Claims(structs.Map(testRequest)), nil},
				},
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testAud, nil},
				},
				{
					Name:    "ApplicationGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testApp, nil},
				},
				{
					Name: "UserAuthenticate",
					Args: litmus.Args{litmus.Context, mock.AnythingOfType("string"), mock.AnythingOfType("string")},
					Returns: litmus.Returns{
						&oauth.User{
							Permissions: oauth.PermissionSet{
								"crypto": oauth.Permissions{"metaverse:read", "metaverse:write", "openid", "profile", "offline_access"},
							},
						}, testPrin, nil},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/login",
			ExpectedStatus:     http.StatusFound,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("login", "hiro@metaverse.org").
				Add("password", "password").
				Add("request_token", testToken).
				Encode(),
		},
		"LoginReqBadUserScope": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenValidate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{oauth.Claims(structs.Map(testRequest)), nil},
				},
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testAud, nil},
				},
				{
					Name:    "ApplicationGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testApp, nil},
				},
				{
					Name: "UserAuthenticate",
					Args: litmus.Args{litmus.Context, mock.AnythingOfType("string"), mock.AnythingOfType("string")},
					Returns: litmus.Returns{
						&oauth.User{
							Permissions: oauth.PermissionSet{
								"snowcrash": oauth.Permissions{"foo"},
							},
						}, testPrin, nil},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/login",
			ExpectedStatus:     http.StatusFound,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("login", "hiro@metaverse.org").
				Add("password", "password").
				Add("request_token", testToken).
				Encode(),
		},
		"LoginSessionCreateFail": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenValidate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{oauth.Claims(structs.Map(testRequest)), nil},
				},
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testAud, nil},
				},
				{
					Name:    "ApplicationGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testApp, nil},
				},
				{
					Name:    "UserAuthenticate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string"), mock.AnythingOfType("string")},
					Returns: litmus.Returns{testUser, testPrin, nil},
				},
				{
					Name:    "SessionCreate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("*http.Request")},
					Returns: litmus.Returns{nil, errors.New("bad session")},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/login",
			ExpectedStatus:     http.StatusFound,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("login", "hiro@metaverse.org").
				Add("password", "password").
				Add("request_token", testToken).
				Encode(),
		},
		"LoginAuthCodeCreateFail": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenValidate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{oauth.Claims(structs.Map(testRequest)), nil},
				},
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testAud, nil},
				},
				{
					Name:    "ApplicationGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testApp, nil},
				},
				{
					Name:    "UserAuthenticate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string"), mock.AnythingOfType("string")},
					Returns: litmus.Returns{testUser, testPrin, nil},
				},
				{
					Name:    "SessionCreate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("*http.Request")},
					Returns: litmus.Returns{testSession, nil},
				},
				{
					Name:    "AuthCodeCreate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("*oauth.AuthCode")},
					Returns: litmus.Returns{errors.New("authcode create failed")},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/login",
			ExpectedStatus:     http.StatusFound,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("login", "hiro@metaverse.org").
				Add("password", "password").
				Add("request_token", testToken).
				Encode(),
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
