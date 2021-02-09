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
	"net/http"
	"testing"

	"github.com/apex/log"
	"github.com/fatih/structs"
	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/litmus/pkg/litmus"
	"github.com/libatomic/oauth/pkg/oauth"
	"github.com/stretchr/testify/mock"
)

func TestPasswordCreate(t *testing.T) {
	auth := new(MockAuthorizer)

	tests := map[string]litmus.Test{
		"PasswordCreate": {
			Operations: []litmus.Operation{
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
					Name:    "TokenValidate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{oauth.Claims(structs.Map(testRequest)), nil},
				},
				{
					Name:    "UserGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testUser, testUser, nil},
				},
				{
					Name:    "TokenFinalize",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("oauth.Claims")},
					Returns: litmus.Returns{"", nil},
				},
			},
			Method: http.MethodPost,
			Path:   "/oauth/password",
			Request: PasswordCreateParams{
				Login:        &testUser.Login,
				Type:         PasswordTypeLink,
				RequestToken: &testToken,
				CodeVerifier: &verifier,
				Notify:       []oauth.NotificationChannel{"email"},
			},
			ExpectedStatus: http.StatusFound,
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/`,
			},
		},
		"PasswordCreateUser": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenFinalize",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("oauth.Claims")},
					Returns: litmus.Returns{"", nil},
				},
			},
			Method: http.MethodPost,
			Path:   "/oauth/password",
			Request: PasswordCreateParams{
				Type:        PasswordTypeLink,
				RedirectURI: (*oauth.URI)(&testRequest.RedirectURI),
				Notify:      []oauth.NotificationChannel{"email"},
			},
			Setup: func(r *http.Request) {
				auth.Handler(func(r *http.Request) (context.Context, error) {
					return oauth.NewContext(
						r.Context(),
						oauth.Context{
							Audience:    testAud,
							Application: testApp,
							User:        testUser,
							Principal:   testUser,
						}), nil
				})
			},
			ExpectedStatus: http.StatusAccepted,
		},
		"PasswordCreateReset": {
			Operations: []litmus.Operation{
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
					Name:    "TokenValidate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{oauth.Claims(structs.Map(testRequest)), nil},
				},
				{
					Name:    "UserGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testUser, testUser, nil},
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
			Method: http.MethodPost,
			Path:   "/oauth/password",
			Request: PasswordCreateParams{
				Login:        &testUser.Login,
				Type:         PasswordTypeReset,
				RequestToken: &testToken,
				CodeVerifier: &verifier,
				Notify:       []oauth.NotificationChannel{"email"},
			},
			ExpectedStatus: http.StatusFound,
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/`,
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := new(MockController)

			mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(auth))

			test.Do(&ctrl.Mock, mockServer, t)
		})
	}
}

func TestPasswordUpdate(t *testing.T) {
	auth := new(MockAuthorizer)

	tests := map[string]litmus.Test{
		"PasswordUpdate": {
			Operations: []litmus.Operation{
				{
					Name:    "AuthCodeGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testCode, nil},
				},
				{
					Name:    "AuthCodeDestroy",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{nil},
				},
			},
			Method: http.MethodPut,
			Path:   "/oauth/password",
			Request: PasswordUpdateParams{
				Password:    "foo",
				ResetCode:   testCode.Code,
				RedirectURI: (*oauth.URI)(&testRequest.RedirectURI),
			},
			Setup: func(r *http.Request) {
				auth.Handler(func(r *http.Request) (context.Context, error) {
					return oauth.NewContext(
						r.Context(),
						oauth.Context{
							Audience:    testAud,
							Application: testApp,
							User:        testUser,
							Principal:   testUser,
						}), nil
				})
			},
			ExpectedStatus: http.StatusFound,
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/`,
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := new(MockController)

			mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(auth))

			test.Do(&ctrl.Mock, mockServer, t)
		})
	}
}
