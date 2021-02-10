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

func TestPasswordCreateOK(t *testing.T) {
	auth := new(MockAuthorizer)

	test := litmus.Test{
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
				Name:    "UserNotify",
				Args:    litmus.Args{litmus.Context, mock.AnythingOfType("server.passwordNotification")},
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
			Type:         PasswordTypeLink,
			RequestToken: &testToken,
			CodeVerifier: &verifier,
			Notify:       []oauth.NotificationChannel{"email"},
		},
		ExpectedStatus: http.StatusFound,
		ExpectedHeaders: map[string]string{
			"Location": `https:\/\/meta\.org\/`,
		},
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(auth))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestPasswordCreateNoRedirect(t *testing.T) {
	auth := new(MockAuthorizer)

	testRequest := *testRequest
	testRequest.AppURI = ""
	testToken := mockRequestToken(&testRequest)
	test := litmus.Test{
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
				Name:    "UserNotify",
				Args:    litmus.Args{litmus.Context, mock.AnythingOfType("server.passwordNotification")},
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
			Type:         PasswordTypeLink,
			RequestToken: &testToken,
			CodeVerifier: &verifier,
			Notify:       []oauth.NotificationChannel{"email"},
		},
		ExpectedStatus: http.StatusAccepted,
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(auth))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestPasswordCreateErrNotify(t *testing.T) {
	auth := new(MockAuthorizer)

	test := litmus.Test{
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
				Name:    "UserNotify",
				Args:    litmus.Args{litmus.Context, mock.AnythingOfType("server.passwordNotification")},
				Returns: litmus.Returns{oauth.ErrUserNotFound},
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
			"Location": `https:\/\/meta\.org\/\?error=internal_server_error`,
		},
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(auth))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestPasswordCreateErrSignRequest(t *testing.T) {
	auth := new(MockAuthorizer)

	test := litmus.Test{
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
				Returns: litmus.Returns{nil, oauth.ErrInvalidToken},
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
			"Location": `https:\/\/meta\.org\/\?error=internal_server_error.?`,
		},
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(auth))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestPasswordCreateErrFinalizeToken(t *testing.T) {
	auth := new(MockAuthorizer)

	test := litmus.Test{
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
				Name: "TokenFinalize",
				Args: litmus.Args{litmus.Context, mock.AnythingOfType("oauth.Claims")},
				ReturnStack: litmus.ReturnStack{
					litmus.Returns{"", nil},
					litmus.Returns{nil, oauth.ErrInvalidToken},
				},
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
			"Location": `https:\/\/meta\.org\/\?error=internal_server_error.?`,
		},
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(auth))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestPasswordResetOK(t *testing.T) {
	auth := new(MockAuthorizer)

	testRequest := *testRequest
	testRequest.Scope = testRequest.Scope.Without("password")
	testToken := mockRequestToken(&testRequest)

	test := litmus.Test{
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
				Name:    "UserNotify",
				Args:    litmus.Args{litmus.Context, mock.AnythingOfType("server.passwordNotification")},
				Returns: litmus.Returns{nil},
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
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(auth))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestPasswordResetErrAuthCode(t *testing.T) {
	auth := new(MockAuthorizer)

	testRequest := *testRequest
	testRequest.Scope = testRequest.Scope.Without("password")
	testToken := mockRequestToken(&testRequest)

	test := litmus.Test{
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
				Returns: litmus.Returns{oauth.ErrInvalidInviteCode},
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
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(auth))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestPasswordCreate(t *testing.T) {
	auth := new(MockAuthorizer)

	altURI := oauth.URI(altURI)

	appURI := oauth.URI(mockURI)

	tests := map[string]litmus.Test{
		"PasswordCreateRedirectOverride": {
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
				{
					Name:    "UserNotify",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("server.passwordNotification")},
					Returns: litmus.Returns{nil},
				},
			},
			Method: http.MethodPost,
			Path:   "/oauth/password",
			Request: PasswordCreateParams{
				Login:        &testUser.Login,
				Type:         PasswordTypeLink,
				RedirectURI:  &altURI,
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
				{
					Name:    "UserNotify",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("server.passwordNotification")},
					Returns: litmus.Returns{nil},
				},
			},
			Method: http.MethodPost,
			Path:   "/oauth/password",
			Request: PasswordCreateParams{
				Type:        PasswordTypeLink,
				RedirectURI: (*oauth.URI)(&testRequest.RedirectURI),
				AppURI:      &appURI,
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
			ExpectedStatus: http.StatusFound,
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

func TestPasswordErrBadContext(t *testing.T) {
	auth := new(MockAuthorizer)

	test := litmus.Test{
		Operations: []litmus.Operation{
			{
				Name:    "AudienceGet",
				Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
				Returns: litmus.Returns{nil, oauth.ErrAudienceNotFound},
			},
			{
				Name:    "TokenValidate",
				Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
				Returns: litmus.Returns{oauth.Claims(structs.Map(testRequest)), nil},
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
			"Location": `https:\/\/meta\.org\/\?error=forbidden&error_description=invalid\+context`,
		},
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(auth))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestPasswordErrTokenValidate(t *testing.T) {
	test := litmus.Test{
		Operations: []litmus.Operation{
			{
				Name:    "TokenValidate",
				Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
				Returns: litmus.Returns{nil, oauth.ErrInvalidToken},
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
		ExpectedStatus: http.StatusBadRequest,
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(ctrl))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestPasswordErrBadAppURI(t *testing.T) {
	testRequest := *testRequest
	testRequest.AppURI = `https://ffiis\\n`
	testToken := mockRequestToken(&testRequest)

	test := litmus.Test{
		Operations: []litmus.Operation{
			{
				Name:    "TokenValidate",
				Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
				Returns: litmus.Returns{oauth.Claims(structs.Map(testRequest)), nil},
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
		ExpectedStatus: http.StatusBadRequest,
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(ctrl))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestPasswordErrExpiredRequest(t *testing.T) {
	testRequest := *testRequest
	testRequest.ExpiresAt = time.Now().Unix()
	testToken := mockRequestToken(&testRequest)

	test := litmus.Test{
		Operations: []litmus.Operation{
			{
				Name:    "TokenValidate",
				Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
				Returns: litmus.Returns{oauth.Claims(structs.Map(testRequest)), nil},
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
			"Location": `https:\/\/meta\.org\/\?error=unauthorized&.?`,
		},
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(ctrl))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestPasswordErrMissingCodeVerifier(t *testing.T) {
	test := litmus.Test{
		Operations: []litmus.Operation{
			{
				Name:    "TokenValidate",
				Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
				Returns: litmus.Returns{oauth.Claims(structs.Map(testRequest)), nil},
			},
		},
		Method: http.MethodPost,
		Path:   "/oauth/password",
		Request: PasswordCreateParams{
			Login:        &testUser.Login,
			Type:         PasswordTypeLink,
			RequestToken: &testToken,
			Notify:       []oauth.NotificationChannel{"email"},
		},
		ExpectedStatus: http.StatusFound,
		ExpectedHeaders: map[string]string{
			"Location": `https:\/\/meta\.org\/\?error=bad_request&.?`,
		},
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(ctrl))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestPasswordErrBadChallenge(t *testing.T) {
	testRequest := *testRequest
	testRequest.CodeChallenge = &verifier
	testToken := mockRequestToken(&testRequest)

	test := litmus.Test{
		Operations: []litmus.Operation{
			{
				Name:    "TokenValidate",
				Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
				Returns: litmus.Returns{oauth.Claims(structs.Map(testRequest)), nil},
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
			"Location": `https:\/\/meta\.org\/\?error=unauthorized&.?`,
		},
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(ctrl))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestPasswordErrBadUser(t *testing.T) {
	auth := new(MockAuthorizer)

	test := litmus.Test{
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
				Returns: litmus.Returns{nil, nil, oauth.ErrUserNotFound},
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
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(auth))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestPasswordErrBadRedirectURI(t *testing.T) {
	auth := new(MockAuthorizer)

	badURI := oauth.URI("https://foo")

	test := litmus.Test{
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
		},
		Method: http.MethodPost,
		Path:   "/oauth/password",
		Request: PasswordCreateParams{
			Login:        &testUser.Login,
			Type:         PasswordTypeLink,
			RequestToken: &testToken,
			RedirectURI:  &badURI,
			CodeVerifier: &verifier,
			Notify:       []oauth.NotificationChannel{"email"},
		},
		ExpectedStatus: http.StatusFound,
		ExpectedHeaders: map[string]string{
			"Location": `https:\/\/meta\.org\/`,
		},
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(auth))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestPasswordErrMissingRedirectURI(t *testing.T) {
	auth := new(MockAuthorizer)
	appURI := oauth.URI(mockURI)
	test := litmus.Test{
		Operations: []litmus.Operation{},
		Method:     http.MethodPost,
		Path:       "/oauth/password",
		Request: PasswordCreateParams{
			Type:   PasswordTypeLink,
			AppURI: &appURI,
			Notify: []oauth.NotificationChannel{"email"},
		},
		Setup: func(r *http.Request) {
			auth.Handler(func(r *http.Request) (context.Context, error) {
				return oauth.NewContext(
					r.Context(),
					oauth.Context{
						User: testUser,
					}), nil
			})
		},
		ExpectedStatus: http.StatusFound,
		ExpectedHeaders: map[string]string{
			"Location": `https:\/\/meta\.org\/`,
		},
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(auth))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestPasswordErrMissingUser(t *testing.T) {
	auth := new(MockAuthorizer)
	appURI := oauth.URI(mockURI)
	test := litmus.Test{
		Operations: []litmus.Operation{},
		Method:     http.MethodPost,
		Path:       "/oauth/password",
		Request: PasswordCreateParams{
			Type:        PasswordTypeLink,
			AppURI:      &appURI,
			RedirectURI: &appURI,
			Notify:      []oauth.NotificationChannel{"email"},
		},
		Setup: func(r *http.Request) {
			auth.Handler(func(r *http.Request) (context.Context, error) {
				return oauth.NewContext(
					r.Context(),
					oauth.Context{
						User: nil,
					}), nil
			})
		},
		ExpectedStatus: http.StatusFound,
		ExpectedHeaders: map[string]string{
			"Location": `https:\/\/meta\.org\/`,
		},
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(auth))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestPasswordUpdate(t *testing.T) {
	auth := new(MockAuthorizer)

	test := litmus.Test{
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
			{
				Name:    "UserSetPassword",
				Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string"),  mock.AnythingOfType("string")},
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
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(auth))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestPasswordUpdateErrAuthCode(t *testing.T) {
	auth := new(MockAuthorizer)

	test := litmus.Test{
		Operations: []litmus.Operation{
			{
				Name:    "AuthCodeGet",
				Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
				Returns: litmus.Returns{nil, oauth.ErrInvalidToken},
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
		ExpectedStatus: http.StatusUnauthorized,
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(auth))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestPasswordUpdateErrSubject(t *testing.T) {
	auth := new(MockAuthorizer)

	testCode := *testCode

	testCode.Subject = "1234"

	test := litmus.Test{
		Operations: []litmus.Operation{
			{
				Name:    "AuthCodeGet",
				Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
				Returns: litmus.Returns{&testCode, nil},
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
		ExpectedStatus: http.StatusUnauthorized,
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(auth))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestPasswordUpdateErrSetPassword(t *testing.T) {
	auth := new(MockAuthorizer)

	test := litmus.Test{
		Operations: []litmus.Operation{
			{
				Name:    "AuthCodeGet",
				Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
				Returns: litmus.Returns{testCode, nil},
			},
			{
				Name:    "UserSetPassword",
				Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string"),  mock.AnythingOfType("string")},
				Returns: litmus.Returns{oauth.ErrUserNotFound},
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
		ExpectedStatus: http.StatusInternalServerError,
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(auth))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestPasswordUpdateNoRedirect(t *testing.T) {
	auth := new(MockAuthorizer)

	test := litmus.Test{
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
			{
				Name:    "UserSetPassword",
				Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string"),  mock.AnythingOfType("string")},
				Returns: litmus.Returns{nil},
			},
		},
		Method: http.MethodPut,
		Path:   "/oauth/password",
		Request: PasswordUpdateParams{
			Password:    "foo",
			ResetCode:   testCode.Code,
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
		ExpectedStatus: http.StatusNoContent,
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAuthorizer(auth))

	test.Do(&ctrl.Mock, mockServer, t)
}