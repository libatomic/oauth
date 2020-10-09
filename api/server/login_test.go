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

func TestLogin(t *testing.T) {
	tests := map[string]litmus.Test{
		"LoginOK": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenPublicKey",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{&testKey.PublicKey, nil},
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
				Add("code_verifier", verifier).
				Add("request_token", testToken).
				Encode(),
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/\?code=00000000-0000-0000-0000-000000000000`,
			},
		},
		"LoginOKEmptyScope": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenPublicKey",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{&testKey.PublicKey, nil},
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
				Add("code_verifier", verifier).
				Add("request_token", emptyScopeToken).
				Encode(),
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/\?code=00000000-0000-0000-0000-000000000000`,
			},
		},
		"LoginBadKey": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenPublicKey",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{nil, errors.New("bad key")},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/login",
			ExpectedStatus:     http.StatusInternalServerError,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("login", "hiro@metaverse.org").
				Add("password", "password").
				Add("code_verifier", verifier).
				Add("request_token", testToken).
				Encode(),
		},
		"LoginBadToken": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenPublicKey",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{&testKey.PublicKey, nil},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/login",
			ExpectedStatus:     http.StatusBadRequest,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("login", "hiro@metaverse.org").
				Add("password", "password").
				Add("code_verifier", verifier).
				Add("request_token", "bad-token").
				Encode(),
			ExpectedResponse: `
{
	"message": "illegal base64 data at input byte 8"
}`,
		},
		"LoginExpiredToken": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenPublicKey",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{&testKey.PublicKey, nil},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/login",
			ExpectedStatus:     http.StatusUnauthorized,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("login", "hiro@metaverse.org").
				Add("password", "password").
				Add("code_verifier", verifier).
				Add("request_token", expiredToken).
				Encode(),
		},
		"LoginBadVerifier": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenPublicKey",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{&testKey.PublicKey, nil},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/login",
			ExpectedStatus:     http.StatusFound,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("login", "hiro@metaverse.org").
				Add("password", "password").
				Add("code_verifier", verifier+"bad stuff").
				Add("request_token", testToken).
				Encode(),
		},
		"LoginBadChallenge": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenPublicKey",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{&testKey.PublicKey, nil},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/login",
			ExpectedStatus:     http.StatusFound,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("login", "hiro@metaverse.org").
				Add("password", "password").
				Add("code_verifier", verifier).
				Add("request_token", badToken).
				Encode(),
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/\?error=bad_request&error_description=invalid\+code_challenge`,
			},
		},
		"LoginMismatchChallenge": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenPublicKey",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{&testKey.PublicKey, nil},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/login",
			ExpectedStatus:     http.StatusFound,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("login", "hiro@metaverse.org").
				Add("password", "password").
				Add("code_verifier", verifier).
				Add("request_token", misMatchToken).
				Encode(),
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/\?error=bad_request&error_description=code\+verification\+failed`,
			},
		},
		"LoginContextError": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenPublicKey",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{&testKey.PublicKey, nil},
				},
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{nil, errors.New("bad stuff")},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/login",
			ExpectedStatus:     http.StatusFound,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("login", "hiro@metaverse.org").
				Add("password", "password").
				Add("code_verifier", verifier).
				Add("request_token", testToken).
				Encode(),
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/\?error=bad_request&error_description=context\+verification\+failed`,
			},
		},
		"LoginAuthFail": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenPublicKey",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{&testKey.PublicKey, nil},
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
				Add("code_verifier", verifier).
				Add("request_token", testToken).
				Encode(),
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/\?error=access_denied&error_description=user\+authentication\+failed`,
			},
		},
		"LoginUserAudMissing": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenPublicKey",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{&testKey.PublicKey, nil},
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
				Add("code_verifier", verifier).
				Add("request_token", testToken).
				Encode(),
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/\?error=access_denied&error_description=user\+authorization\+failed`,
			},
		},
		"LoginReqBadUserScope": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenPublicKey",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{&testKey.PublicKey, nil},
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
				Add("code_verifier", verifier).
				Add("request_token", testToken).
				Encode(),
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/\?error=access_denied&error_description=user\+authorization\+failed`,
			},
		},
		"LoginMissingSession": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenPublicKey",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{&testKey.PublicKey, nil},
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
				Add("code_verifier", verifier).
				Add("request_token", testToken).
				Encode(),
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/\?error=server_error&error_description=bad\+session`,
			},
		},
		"LoginAuthCodeCreateFail": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenPublicKey",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{&testKey.PublicKey, nil},
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
				Add("code_verifier", verifier).
				Add("request_token", testToken).
				Encode(),
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/\?error=server_error&error_description=authcode\+create\+failed`,
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
