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

	test := litmus.Test{

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
	}

	ctrl := new(MockController)

	auth := oauth.NewAuthorizer(ctrl, oauth.WithPermitQueryToken(true))

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(auth))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestSessionErrExpiredToken(t *testing.T) {
	scopedRequest := scopeRequest(testRequest, "session")
	expired, _ := mockAccessToken(scopedRequest, time.Now())

	test := litmus.Test{
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
	}

	ctrl := new(MockController)

	auth := oauth.NewAuthorizer(ctrl, oauth.WithPermitQueryToken(true))

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(auth))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestSessionErrTokenValidate(t *testing.T) {
	test := litmus.Test{
		Operations: []litmus.Operation{
			{
				Name:    "TokenValidate",
				Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
				Returns: litmus.Returns{nil, oauth.ErrInvalidToken},
			},
		},
		Method: http.MethodGet,
		Path:   "/oauth/session",
		Query: litmus.BeginQuery().
			Add("access_token", testToken).
			EndQuery(),
		Request: SessionParams{
			RequestToken: testToken,
			RedirectURI:  (*oauth.URI)(&testRequest.RedirectURI),
			AuthCode:     true,
		},
		ExpectedStatus: http.StatusUnauthorized,
	}

	ctrl := new(MockController)

	auth := oauth.NewAuthorizer(ctrl, oauth.WithPermitQueryToken(true))

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(auth))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestSessionErrAccessDenied(t *testing.T) {
	auth := new(MockAuthorizer)

	scopedRequest := scopeRequest(testRequest, "session")
	token, _ := mockAccessToken(scopedRequest, time.Now().Add(time.Minute*5))

	test := litmus.Test{

		Operations: []litmus.Operation{
			{
				Name:    "TokenValidate",
				Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
				Returns: litmus.Returns{oauth.Claims(structs.Map(scopedRequest)), nil},
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
		Setup: func(r *http.Request) {
			auth.Handler(func(r *http.Request) (context.Context, error) {
				return oauth.NewContext(
					r.Context(),
					oauth.Context{
						Error: oauth.ErrAccessDenied,
					}), nil
			})
		},
		ExpectedStatus: http.StatusFound,
		ExpectedHeaders: map[string]string{
			"Location": `https:\/\/meta\.org\/\?error=unauthorized`,
		},
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(auth))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestSessionErrExpiredRequest(t *testing.T) {
	scopedRequest := scopeRequest(testRequest, "session")
	token, _ := mockAccessToken(scopedRequest, time.Now().Add(time.Minute*5))

	scopedRequest.ExpiresAt = time.Now().Unix()

	test := litmus.Test{

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
			"Location": `https:\/\/meta\.org\/\?error=unauthorized`,
		},
	}

	ctrl := new(MockController)

	auth := oauth.NewAuthorizer(ctrl, oauth.WithPermitQueryToken(true))

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(auth))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestSessionErrMissingSubject(t *testing.T) {
	scopedRequest := scopeRequest(testRequest, "session")
	token, _ := mockAccessToken(scopedRequest, time.Now().Add(time.Minute*5))

	scopedRequest.Subject = nil

	test := litmus.Test{

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
				Name:    "TokenValidate",
				Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
				Returns: litmus.Returns{oauth.Claims(structs.Map(scopedRequest)), nil},
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
			"Location": `https:\/\/meta\.org\/\?error=forbidden`,
		},
	}

	ctrl := new(MockController)

	auth := oauth.NewAuthorizer(ctrl, oauth.WithPermitQueryToken(true))

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(auth))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestSessionErrBadSubject(t *testing.T) {
	scopedRequest := scopeRequest(testRequest, "session")
	token, _ := mockAccessToken(scopedRequest, time.Now().Add(time.Minute*5))

	badSubRequest := *scopedRequest
	sub := "1234"
	badSubRequest.Subject = &sub

	test := litmus.Test{
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
				Name: "TokenValidate",
				Args: litmus.Args{litmus.Context, mock.AnythingOfType("string")},
				ReturnStack: litmus.ReturnStack{
					litmus.Returns{oauth.Claims(structs.Map(scopedRequest)), nil},
					litmus.Returns{oauth.Claims(structs.Map(badSubRequest)), nil},
				},
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
			"Location": `https:\/\/meta\.org\/\?error=forbidden`,
		},
	}

	ctrl := new(MockController)

	auth := oauth.NewAuthorizer(ctrl, oauth.WithPermitQueryToken(true))

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(auth))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestSessionErrSessionCreate(t *testing.T) {
	scopedRequest := scopeRequest(testRequest, "session")
	token, _ := mockAccessToken(scopedRequest, time.Now().Add(time.Minute*5))

	test := litmus.Test{

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
				Returns: litmus.Returns{nil, oauth.ErrUnsupportedAlogrithm},
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
			"Location": `https:\/\/meta\.org\/\?error=internal_server_error`,
		},
	}

	ctrl := new(MockController)

	auth := oauth.NewAuthorizer(ctrl, oauth.WithPermitQueryToken(true))

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(auth))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestSessionErrAuthCode(t *testing.T) {
	scopedRequest := scopeRequest(testRequest, "session")
	token, _ := mockAccessToken(scopedRequest, time.Now().Add(time.Minute*5))

	test := litmus.Test{

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
				Returns: litmus.Returns{oauth.ErrInvalidToken},
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
			"Location": `https:\/\/meta\.org\/\?error=internal_server_error`,
		},
	}

	ctrl := new(MockController)

	auth := oauth.NewAuthorizer(ctrl, oauth.WithPermitQueryToken(true))

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(auth))

	test.Do(&ctrl.Mock, mockServer, t)
}