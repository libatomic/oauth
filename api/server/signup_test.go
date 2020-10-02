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
	"github.com/stretchr/testify/mock"
)

func TestSignup(t *testing.T) {
	tests := map[string]litmus.Test{
		"SingupOK": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenPublicKey",
					Args:    litmus.Args{litmus.Context},
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
					Name: "UserCreate",
					Args: litmus.Args{
						litmus.Context,
						mock.AnythingOfType("oauth.User"),
						mock.AnythingOfType("string")},
					Returns: litmus.Returns{testUser, nil},
				},
				{
					Name:    "UserAuthenticate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string"), mock.AnythingOfType("string")},
					Returns: litmus.Returns{testUser, testPrin, nil},
				},
				{
					Name:    "SessionCreate",
					Args:    litmus.Args{mock.AnythingOfType("*http.Request"), mock.AnythingOfType("*oauth.Context")},
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
				Add("code_verifier", verifier).
				Add("request_token", testToken).
				Encode(),
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/\?code=00000000-0000-0000-0000-000000000000`,
			},
		},
		"SignupBadKey": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenPublicKey",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{nil, errors.New("invalid key")},
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
				Add("code_verifier", verifier).
				Add("request_token", testToken).
				Encode(),
			ExpectedResponse: `
{
	"message": "invalid key"
}`,
		},
		"SignupBadToken": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenPublicKey",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{&testKey.PublicKey, nil},
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
				Add("code_verifier", verifier).
				Add("request_token", "bad-token").
				Encode(),
			ExpectedResponse: `
{
	"message": "illegal base64 data at input byte 8"
}`,
		},
		"SignupExpiredToken": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenPublicKey",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{&testKey.PublicKey, nil},
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
				Add("code_verifier", verifier).
				Add("request_token", expiredToken).
				Encode(),
		},
		"SignupBadContext": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenPublicKey",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{&testKey.PublicKey, nil},
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
				Add("code_verifier", verifier).
				Add("request_token", testToken).
				Encode(),
		},
		"SingupUserCreateError": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenPublicKey",
					Args:    litmus.Args{litmus.Context},
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
					Name: "UserCreate",
					Args: litmus.Args{
						litmus.Context,
						mock.AnythingOfType("oauth.User"),
						mock.AnythingOfType("string")},
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
				Add("code_verifier", verifier).
				Add("request_token", testToken).
				Encode(),
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
