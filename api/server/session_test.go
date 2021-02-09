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
	"time"

	"github.com/apex/log"
	"github.com/fatih/structs"
	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/litmus/pkg/litmus"
	"github.com/libatomic/oauth/pkg/oauth"
	"github.com/stretchr/testify/mock"
)

func TestSession(t *testing.T) {
	scopedRequest := scopeRequest(testRequest, "session")
	token, _ := mockAccessToken(scopedRequest, time.Now().Add(time.Minute*5))
	expired, _ := mockAccessToken(scopedRequest, time.Now())

	tests := map[string]litmus.Test{
		"Session": {
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
					Name:    "UserGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testUser, testPrin, nil},
				},
				{
					Name:    "TokenValidate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{oauth.Claims(structs.Map(scopedRequest)), nil},
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
			Method: http.MethodGet,
			Path:   "/oauth/session",
			Query: litmus.BeginQuery().
				Add("access_token", token).
				EndQuery(),
			Request: SessionParams{
				RequestToken: testToken,
				RedirectURI:  (*oauth.URI)(&testRequest.RedirectURI),
				AuthCode:     true,
			},
			ExpectedStatus: http.StatusFound,
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/`,
			},
		},
		"SessionExpiredToken": {
			Operations: []litmus.Operation{
				{
					Name: "TokenValidate",
					Args: litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					ReturnStack: litmus.ReturnStack{
						litmus.Returns{nil, oauth.ErrExpiredToken},
						litmus.Returns{oauth.Claims(structs.Map(testRequest)), nil},
					},
				},
			},
			Method: http.MethodGet,
			Path:   "/oauth/session",
			Query: litmus.BeginQuery().
				Add("access_token", expired).
				EndQuery(),
			Request: SessionParams{
				RequestToken: testToken,
				RedirectURI:  (*oauth.URI)(&testRequest.RedirectURI),
				AuthCode:     true,
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

			auth := oauth.NewAuthorizer(ctrl, oauth.WithPermitQueryToken(true))

			mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(auth))

			test.Do(&ctrl.Mock, mockServer, t)
		})
	}
}
