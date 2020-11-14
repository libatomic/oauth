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

func TestSignup(t *testing.T) {
	tests := map[string]litmus.Test{
		"SingupOK": {
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
					Name: "UserCreate",
					Args: litmus.Args{
						litmus.Context,
						mock.AnythingOfType("string"),
						mock.AnythingOfType("string"),
						mock.AnythingOfType("*oauth.Profile"),
					},
					Returns: litmus.Returns{testUser, nil},
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
			Path:               "/oauth/signup",
			ExpectedStatus:     http.StatusFound,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("login", "hiro@metaverse.org").
				Add("email", "hiro@metaverse.org").
				Add("password", "password").
				Add("request_token", testToken).
				Encode(),
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/\?code=00000000-0000-0000-0000-000000000000`,
			},
		},
		"SignupBadToken": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenValidate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{oauth.Claims(structs.Map(testRequest)), errors.New("bad token")},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/signup",
			ExpectedStatus:     http.StatusBadRequest,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("login", "hiro@metaverse.org").
				Add("email", "hiro@metaverse.org").
				Add("password", "password").
				Add("request_token", "bad-token").
				Encode(),
		},
		"SignupExpiredToken": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenValidate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{oauth.Claims(structs.Map(expiredReq)), nil},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/signup",
			ExpectedStatus:     http.StatusUnauthorized,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("login", "hiro@metaverse.org").
				Add("password", "password").
				Add("email", "hiro@metaverse.org").
				Add("request_token", expiredToken).
				Encode(),
		},
		"SignupBadContext": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenValidate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{oauth.Claims(structs.Map(testRequest)), nil},
				},
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{nil, errors.New("audience not found")},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/signup",
			ExpectedStatus:     http.StatusInternalServerError,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("login", "hiro@metaverse.org").
				Add("email", "hiro@metaverse.org").
				Add("password", "password").
				Add("request_token", testToken).
				Encode(),
		},
		"SingupUserCreateError": {
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
					Name: "UserCreate",
					Args: litmus.Args{
						litmus.Context,
						mock.AnythingOfType("string"),
						mock.AnythingOfType("string"),
						mock.AnythingOfType("*oauth.Profile"),
					},
					Returns: litmus.Returns{nil, errors.New("bad user")},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/signup",
			ExpectedStatus:     http.StatusBadRequest,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("login", "hiro@metaverse.org").
				Add("email", "hiro@metaverse.org").
				Add("password", "password").
				Add("request_token", testToken).
				Encode(),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := new(mockController)

			mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl))

			test.Do(&ctrl.Mock, mockServer, t)
		})
	}
}
