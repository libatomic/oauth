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
	"github.com/fatih/structs"
	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/litmus/pkg/litmus"
	"github.com/libatomic/oauth/pkg/oauth"
	"github.com/stretchr/testify/mock"
)

func TestSignup(t *testing.T) {
	password := "foo"

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
						mock.AnythingOfType("*string"),
						mock.AnythingOfType("*oauth.Profile"),
						mock.AnythingOfType("[]string"),
					},
					Returns: litmus.Returns{testUser, nil},
				},
				{
					Name:    "UserNotify",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("*server.verifyNotification")},
					Returns: litmus.Returns{nil},
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
				{
					Name:    "TokenFinalize",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("oauth.Claims")},
					Returns: litmus.Returns{"", nil},
				},
			},
			Method:         http.MethodPost,
			Path:           "/oauth/signup",
			ExpectedStatus: http.StatusFound,
			Request: SignupParams{
				Name:         &testUser.Profile.Name,
				Login:        testUser.Login,
				Email:        &testUser.Login,
				Password:     &password,
				RequestToken: testToken,
			},
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/\?code=00000000-0000-0000-0000-000000000000`,
			},
		},
		"SingupNoPass": {
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
					Name:    "UserNotify",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("*server.verifyNotification")},
					Returns: litmus.Returns{nil},
				},
				{
					Name: "UserCreate",
					Args: litmus.Args{
						litmus.Context,
						mock.AnythingOfType("string"),
						mock.AnythingOfType("*string"),
						mock.AnythingOfType("*oauth.Profile"),
						mock.AnythingOfType("[]string"),
					},
					Returns: litmus.Returns{testUser, nil},
				},
				{
					Name:    "TokenFinalize",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("oauth.Claims")},
					Returns: litmus.Returns{"", nil},
				},
			},
			Method:         http.MethodPost,
			Path:           "/oauth/signup",
			ExpectedStatus: http.StatusFound,
			Request: SignupParams{
				Name:         &testUser.Profile.Name,
				Login:        testUser.Login,
				Email:        &testUser.Login,
				RequestToken: testToken,
			},
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/\?state=foo`,
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
