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
	"time"

	"github.com/apex/log"
	"github.com/go-openapi/strfmt"
	"github.com/google/uuid"
	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/litmus/pkg/litmus"
	"github.com/libatomic/oauth/pkg/oauth"
	"github.com/stretchr/testify/mock"
)

func TestTokenAuthcode(t *testing.T) {
	tests := map[string]litmus.Test{
		"TokenAuthCodeOK": {
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
					Name:    "AuthorizedGrantTypes",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{testGrantTypes},
				},
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
					Name:    "AuthCodeCreate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("*oauth.AuthCode")},
					Returns: litmus.Returns{nil},
				},
				{
					Name:    "UserGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testUser, testPrin, nil},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/token",
			ExpectedStatus:     http.StatusOK,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("grant_type", oauth.GrantTypeAuthCode).
				Add("client_id", "00000000-0000-0000-0000-000000000000").
				Add("audience", "snowcrash").
				Add("scope", "metaverse:read metaverse:write openid profile offline_access").
				Add("code", testCode.Code).
				Add("code_verifier", verifier).
				Add("refresh_nonce", testCode.Code).
				Encode(),
		},
		"TokenAuthBadUserPerms": {
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
					Name:    "AuthorizedGrantTypes",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{testGrantTypes},
				},
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
					Name: "UserGet",
					Args: litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{&oauth.User{
						Login:             "hiro@metaverse.org",
						PasswordExpiresAt: strfmt.DateTime(time.Now().Add(time.Hour)),
						Permissions: oauth.PermissionSet{
							"crypto": oauth.Permissions{"metaverse:read", "metaverse:write", "openid", "profile", "offline_access"},
						},
						Profile: &oauth.Profile{
							Subject:    uuid.Must(uuid.NewRandom()).String(),
							GivenName:  "Hiro",
							FamilyName: "Protagonist",
						},
					}, testPrin, nil},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/token",
			ExpectedStatus:     http.StatusUnauthorized,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("grant_type", oauth.GrantTypeAuthCode).
				Add("client_id", "00000000-0000-0000-0000-000000000000").
				Add("audience", "snowcrash").
				Add("scope", "metaverse:read metaverse:write openid profile offline_access").
				Add("code", testCode.Code).
				Add("code_verifier", verifier).
				Add("refresh_nonce", testCode.Code).
				Encode(),
		},
		"TokenAuthBadAppPerms": {
			Operations: []litmus.Operation{
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testAud, nil},
				},
				{
					Name: "ApplicationGet",
					Args: litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{&oauth.Application{
						ClientID:     "00000000-0000-0000-0000-000000000000",
						ClientSecret: "super-secret",
						Permissions: oauth.PermissionSet{
							"crypto": oauth.Permissions{
								"metaverse:read", "metaverse:write", "openid", "profile", "offline_access"},
						},
						AllowedGrants: oauth.PermissionSet{
							"snowcrash": oauth.Permissions{
								oauth.GrantTypeClientCredentials,
								oauth.GrantTypeAuthCode,
								oauth.GrantTypePassword,
								oauth.GrantTypeRefreshToken,
							},
						},
						AppUris: oauth.PermissionSet{
							"snowcrash": oauth.Permissions{mockURI},
						},
						RedirectUris: oauth.PermissionSet{
							"snowcrash": oauth.Permissions{mockURI},
						},
						TokenLifetime: 60,
					}, nil},
				},
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testAud, nil},
				},
				{
					Name:    "AuthorizedGrantTypes",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{testGrantTypes},
				},
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
					Name:    "UserGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testUser, testPrin, nil},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/token",
			ExpectedStatus:     http.StatusUnauthorized,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("grant_type", oauth.GrantTypeAuthCode).
				Add("client_id", "00000000-0000-0000-0000-000000000000").
				Add("audience", "snowcrash").
				Add("scope", "metaverse:read metaverse:write openid profile offline_access").
				Add("code", testCode.Code).
				Add("code_verifier", verifier).
				Add("refresh_nonce", testCode.Code).
				Encode(),
		},
		"TokenAuthCodeEmptyCodeScope": {
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
					Name:    "AuthorizedGrantTypes",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{testGrantTypes},
				},
				{
					Name: "AuthCodeGet",
					Args: litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{&oauth.AuthCode{
						AuthRequest:       emptyScopeReq,
						Code:              "00000000-0000-0000-0000-000000000000",
						IssuedAt:          time.Now().Unix(),
						SessionID:         "00000000-0000-0000-0000-000000000000",
						Subject:           "00000000-0000-0000-0000-000000000000",
						UserAuthenticated: true,
					}, nil},
				},
				{
					Name:    "AuthCodeDestroy",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{nil},
				},
				{
					Name:    "AuthCodeCreate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("*oauth.AuthCode")},
					Returns: litmus.Returns{nil},
				},
				{
					Name:    "UserGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testUser, testPrin, nil},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/token",
			ExpectedStatus:     http.StatusOK,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("grant_type", oauth.GrantTypeAuthCode).
				Add("client_id", "00000000-0000-0000-0000-000000000000").
				Add("audience", "snowcrash").
				Add("code", testCode.Code).
				Add("code_verifier", verifier).
				Add("refresh_nonce", testCode.Code).
				Encode(),
		},
		"TokenAuthCodeOKRS": {
			Operations: []litmus.Operation{
				{
					Name:    "ApplicationGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testApp, nil},
				},
				{
					Name: "AudienceGet",
					Args: litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{&oauth.Audience{
						Name:           "snowcrash",
						Permissions:    oauth.Permissions{"metaverse:read", "metaverse:write", "openid", "profile", "offline_access"},
						TokenAlgorithm: "RS256",
						TokenLifetime:  60,
					}, nil},
				},
				{
					Name:    "AuthorizedGrantTypes",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{testGrantTypes},
				},
				{
					Name:    "TokenPrivateKey",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{testKey, nil},
				},
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
					Name:    "UserGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testUser, testPrin, nil},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/token",
			ExpectedStatus:     http.StatusOK,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("grant_type", oauth.GrantTypeAuthCode).
				Add("client_id", "00000000-0000-0000-0000-000000000000").
				Add("audience", "snowcrash").
				Add("code", testCode.Code).
				Add("code_verifier", verifier).
				Add("scope", "metaverse:read metaverse:write openid profile").
				Add("refresh_nonce", testCode.Code).
				Encode(),
		},
		"TokenAuthCodeErrRS": {
			Operations: []litmus.Operation{
				{
					Name:    "ApplicationGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testApp, nil},
				},
				{
					Name: "AudienceGet",
					Args: litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{&oauth.Audience{
						Name:           "snowcrash",
						Permissions:    oauth.Permissions{"metaverse:read", "metaverse:write", "openid", "profile", "offline_access"},
						TokenAlgorithm: "RS256",
						TokenLifetime:  60,
					}, nil},
				},
				{
					Name:    "AuthorizedGrantTypes",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{testGrantTypes},
				},
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
					Name:    "TokenPrivateKey",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{nil, errors.New("bad key")},
				},
				{
					Name:    "UserGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testUser, testPrin, nil},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/token",
			ExpectedStatus:     http.StatusInternalServerError,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("grant_type", oauth.GrantTypeAuthCode).
				Add("client_id", "00000000-0000-0000-0000-000000000000").
				Add("audience", "snowcrash").
				Add("scope", "metaverse:read metaverse:write openid profile").
				Add("code", testCode.Code).
				Add("code_verifier", verifier).
				Add("refresh_nonce", testCode.Code).
				Encode(),
		},
		"TokenAppErr": {
			Operations: []litmus.Operation{
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testAud, nil},
				},
				{
					Name:    "ApplicationGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{nil, errors.New("bad app")},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/token",
			ExpectedStatus:     http.StatusBadRequest,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("grant_type", oauth.GrantTypeAuthCode).
				Add("client_id", "00000000-0000-0000-0000-000000000000").
				Add("audience", "snowcrash").
				Add("scope", "metaverse:read metaverse:write openid profile offline_access").
				Add("code", testCode.Code).
				Add("code_verifier", verifier).
				Add("refresh_nonce", testCode.Code).
				Encode(),
		},
		"TokenAudErr": {
			Operations: []litmus.Operation{
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{nil, errors.New("bad aud")},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/token",
			ExpectedStatus:     http.StatusBadRequest,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("grant_type", oauth.GrantTypeAuthCode).
				Add("client_id", "00000000-0000-0000-0000-000000000000").
				Add("audience", "snowcrash").
				Add("scope", "metaverse:read metaverse:write openid profile offline_access").
				Add("code", testCode.Code).
				Add("code_verifier", verifier).
				Add("refresh_nonce", testCode.Code).
				Encode(),
		},
		"TokenBadAppGrant": {
			Operations: []litmus.Operation{
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testAud, nil},
				},
				{
					Name: "ApplicationGet",
					Args: litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{&oauth.Application{
						AllowedGrants: oauth.PermissionSet{
							"snowcrash": oauth.Permissions{
								oauth.GrantTypeClientCredentials,
							},
						},
					}, nil},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/token",
			ExpectedStatus:     http.StatusUnauthorized,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("grant_type", oauth.GrantTypeAuthCode).
				Add("client_id", "00000000-0000-0000-0000-000000000000").
				Add("audience", "snowcrash").
				Add("scope", "metaverse:read metaverse:write openid profile offline_access").
				Add("code", testCode.Code).
				Add("code_verifier", verifier).
				Add("refresh_nonce", testCode.Code).
				Encode(),
		},
		"TokenBadScope": {
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
					Name:    "AuthorizedGrantTypes",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{testGrantTypes},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/token",
			ExpectedStatus:     http.StatusUnauthorized,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("grant_type", oauth.GrantTypeAuthCode).
				Add("client_id", "00000000-0000-0000-0000-000000000000").
				Add("audience", "snowcrash").
				Add("scope", "metaverse:delete").
				Add("code", testCode.Code).
				Add("code_verifier", verifier).
				Add("refresh_nonce", testCode.Code).
				Encode(),
		},
		"TokenAuthCodeMissingParams": {
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
					Name:    "AuthorizedGrantTypes",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{testGrantTypes},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/token",
			ExpectedStatus:     http.StatusBadRequest,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("grant_type", oauth.GrantTypeAuthCode).
				Add("client_id", "00000000-0000-0000-0000-000000000000").
				Add("audience", "snowcrash").
				Add("scope", "metaverse:read metaverse:write openid profile offline_access").
				//Add("code", testCode.Code).
				Add("code_verifier", verifier).
				Add("refresh_nonce", testCode.Code).
				Encode(),
		},
		"TokenAuthCodeBadCode": {
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
					Name:    "AuthorizedGrantTypes",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{testGrantTypes},
				},
				{
					Name:    "AuthCodeGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{nil, errors.New("bad code")},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/token",
			ExpectedStatus:     http.StatusUnauthorized,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("grant_type", oauth.GrantTypeAuthCode).
				Add("client_id", "00000000-0000-0000-0000-000000000000").
				Add("audience", "snowcrash").
				Add("scope", "metaverse:read metaverse:write openid profile offline_access").
				Add("code", testCode.Code).
				Add("code_verifier", verifier).
				Add("refresh_nonce", testCode.Code).
				Encode(),
		},
		"TokenAuthCodeBadVerifier": {
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
					Name:    "AuthorizedGrantTypes",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{testGrantTypes},
				},
				{
					Name:    "AuthCodeGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testCode, nil},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/token",
			ExpectedStatus:     http.StatusBadRequest,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("grant_type", oauth.GrantTypeAuthCode).
				Add("client_id", "00000000-0000-0000-0000-000000000000").
				Add("audience", "snowcrash").
				Add("scope", "metaverse:read metaverse:write openid profile offline_access").
				Add("code", testCode.Code).
				Add("code_verifier", "bad verifier").
				Add("refresh_nonce", testCode.Code).
				Encode(),
		},
		"TokenAuthCodeVerfierMismatch": {
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
					Name:    "AuthorizedGrantTypes",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{testGrantTypes},
				},
				{
					Name: "AuthCodeGet",
					Args: litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{&oauth.AuthCode{
						AuthRequest: oauth.AuthRequest{
							ClientID:            "00000000-0000-0000-0000-000000000000",
							RedirectURI:         mockURI,
							Scope:               oauth.Permissions{"metaverse:read", "metaverse:write", "openid", "profile", "offline_access"},
							Audience:            "snowcrash",
							CodeChallenge:       "not a challenge",
							CodeChallengeMethod: "S256",
							ExpiresAt:           time.Now().Add(time.Minute * 10).Unix(),
						},
						Code:              "00000000-0000-0000-0000-000000000000",
						IssuedAt:          time.Now().Unix(),
						SessionID:         "00000000-0000-0000-0000-000000000000",
						Subject:           "00000000-0000-0000-0000-000000000000",
						UserAuthenticated: true,
					}, nil},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/token",
			ExpectedStatus:     http.StatusUnauthorized,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("grant_type", oauth.GrantTypeAuthCode).
				Add("client_id", "00000000-0000-0000-0000-000000000000").
				Add("audience", "snowcrash").
				Add("scope", "metaverse:read metaverse:write openid profile offline_access").
				Add("code", testCode.Code).
				Add("code_verifier", verifier).
				Add("refresh_nonce", testCode.Code).
				Encode(),
		},
		"TokenAuthBadUser": {
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
					Name:    "AuthorizedGrantTypes",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{testGrantTypes},
				},
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
					Name:    "UserGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{nil, nil, errors.New("bad user")},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/token",
			ExpectedStatus:     http.StatusUnauthorized,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("grant_type", oauth.GrantTypeAuthCode).
				Add("client_id", "00000000-0000-0000-0000-000000000000").
				Add("audience", "snowcrash").
				Add("scope", "metaverse:read metaverse:write openid profile offline_access").
				Add("code", testCode.Code).
				Add("code_verifier", verifier).
				Add("refresh_nonce", testCode.Code).
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

func TestTokenPassword(t *testing.T) {
	tests := map[string]litmus.Test{
		"TokenAuthPasswordOK": {
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
					Name:    "AuthorizedGrantTypes",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{testGrantTypes},
				},
				{
					Name:    "UserAuthenticate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string"), mock.AnythingOfType("string")},
					Returns: litmus.Returns{testUser, testPrin, nil},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/token",
			ExpectedStatus:     http.StatusOK,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("grant_type", oauth.GrantTypePassword).
				Add("client_id", testApp.ClientID).
				Add("client_secret", testApp.ClientSecret).
				Add("audience", "snowcrash").
				Add("username", testCode.Code).
				Add("password", verifier).
				Encode(),
		},
		"TokenAuthPasswordBadGrant": {
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
					Name:    "AuthorizedGrantTypes",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{oauth.Permissions{}},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/token",
			ExpectedStatus:     http.StatusUnauthorized,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("grant_type", oauth.GrantTypePassword).
				Add("client_id", testApp.ClientID).
				Add("client_secret", testApp.ClientSecret).
				Add("audience", "snowcrash").
				Add("scope", "metaverse:read metaverse:write openid profile").
				Add("username", testCode.Code).
				Add("password", verifier).
				Encode(),
			ExpectedResponse: `
				{
					"message": "invalid grant type"
				}`,
		},
		"TokenAuthPasswordBadClient": {
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
					Name:    "AuthorizedGrantTypes",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{testGrantTypes},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/token",
			ExpectedStatus:     http.StatusBadRequest,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("grant_type", oauth.GrantTypePassword).
				Add("client_id", "bad client").
				Add("client_secret", testApp.ClientSecret).
				Add("audience", "snowcrash").
				Add("scope", "metaverse:read metaverse:write openid profile").
				Add("username", testCode.Code).
				Add("password", verifier).
				Encode(),
			ExpectedResponse: `
				{
					"message": "bad client id"
				}`,
		},
		"TokenAuthPasswordBadSecret": {
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
					Name:    "AuthorizedGrantTypes",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{testGrantTypes},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/token",
			ExpectedStatus:     http.StatusBadRequest,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("grant_type", oauth.GrantTypePassword).
				Add("client_id", testApp.ClientID).
				Add("client_secret", "bad secret").
				Add("audience", "snowcrash").
				Add("scope", "metaverse:read metaverse:write openid profile").
				Add("username", testCode.Code).
				Add("password", verifier).
				Encode(),
			ExpectedResponse: `
				{
					"message": "bad client secret"
				}`,
		},
		"TokenAuthPasswordMissingUsername": {
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
					Name:    "AuthorizedGrantTypes",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{testGrantTypes},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/token",
			ExpectedStatus:     http.StatusBadRequest,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("grant_type", oauth.GrantTypePassword).
				Add("client_id", testApp.ClientID).
				Add("client_secret", testApp.ClientSecret).
				Add("audience", "snowcrash").
				Add("scope", "metaverse:read metaverse:write openid profile").
				Add("password", verifier).
				Encode(),
			ExpectedResponse: `
				{
					"message": "bad credentials"
				}`,
		},
		"TokenAuthPasswordAuthFailed": {
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
					Name:    "AuthorizedGrantTypes",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{testGrantTypes},
				},
				{
					Name:    "UserAuthenticate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string"), mock.AnythingOfType("string")},
					Returns: litmus.Returns{nil, nil, errors.New("auth failed")},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/token",
			ExpectedStatus:     http.StatusUnauthorized,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("grant_type", oauth.GrantTypePassword).
				Add("client_id", testApp.ClientID).
				Add("client_secret", testApp.ClientSecret).
				Add("audience", "snowcrash").
				Add("scope", "metaverse:read metaverse:write openid profile").
				Add("username", testCode.Code).
				Add("password", verifier).
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

func TestTokenClientCredentials(t *testing.T) {
	tests := map[string]litmus.Test{
		"TokenAuthClientCredsOK": {
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
					Name:    "AuthorizedGrantTypes",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{testGrantTypes},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/token",
			ExpectedStatus:     http.StatusOK,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("grant_type", oauth.GrantTypeClientCredentials).
				Add("client_id", testApp.ClientID).
				Add("client_secret", testApp.ClientSecret).
				Add("user", "hiro@metaverse.net").
				Add("scope", "metaverse:read metaverse:write openid profile").
				Add("audience", "snowcrash").
				Encode(),
		},
		"TokenAuthClientCredsBadSecret": {
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
					Name:    "AuthorizedGrantTypes",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{testGrantTypes},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/token",
			ExpectedStatus:     http.StatusBadRequest,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("grant_type", oauth.GrantTypeClientCredentials).
				Add("client_id", testApp.ClientID).
				Add("client_secret", "bad secret").
				Add("scope", "metaverse:read metaverse:write openid profile").
				Add("audience", "snowcrash").
				Encode(),
		},
		"TokenAuthClientBadScope": {
			Operations: []litmus.Operation{
				{
					Name: "ApplicationGet",
					Args: litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{&oauth.Application{
						ClientID:     "00000000-0000-0000-0000-000000000000",
						ClientSecret: "super-secret",
						Permissions: oauth.PermissionSet{
							"snowcrash": oauth.Permissions{
								"metaverse:destroy", "metaverse:write", "openid", "profile", "offline_access"},
						},
						AllowedGrants: oauth.PermissionSet{
							"snowcrash": oauth.Permissions{
								oauth.GrantTypeClientCredentials,
								oauth.GrantTypeAuthCode,
								oauth.GrantTypePassword,
								oauth.GrantTypeRefreshToken,
							},
						},
						AppUris: oauth.PermissionSet{
							"snowcrash": oauth.Permissions{mockURI},
						},
						RedirectUris: oauth.PermissionSet{
							"snowcrash": oauth.Permissions{mockURI},
						},
						TokenLifetime: 60,
					}, nil},
				},
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testAud, nil},
				},
				{
					Name:    "AuthorizedGrantTypes",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{testGrantTypes},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/token",
			ExpectedStatus:     http.StatusUnauthorized,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("grant_type", oauth.GrantTypeClientCredentials).
				Add("client_id", testApp.ClientID).
				Add("client_secret", testApp.ClientSecret).
				Add("scope", "metaverse:read metaverse:write openid profile").
				Add("audience", "snowcrash").
				Encode(),
		},
		"TokenAuthClientCredsBadToken": {
			Operations: []litmus.Operation{
				{
					Name:    "ApplicationGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testApp, nil},
				},
				{
					Name: "AudienceGet",
					Args: litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{&oauth.Audience{
						Name:           "snowcrash",
						Permissions:    oauth.Permissions{"metaverse:read", "metaverse:write", "openid", "profile", "offline_access"},
						TokenAlgorithm: "RS256",
						TokenLifetime:  60,
					}, nil},
				},
				{
					Name:    "AuthorizedGrantTypes",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{testGrantTypes},
				},
				{
					Name:    "TokenPrivateKey",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{nil, errors.New("bad key")},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/token",
			ExpectedStatus:     http.StatusInternalServerError,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("grant_type", oauth.GrantTypeClientCredentials).
				Add("client_id", testApp.ClientID).
				Add("client_secret", testApp.ClientSecret).
				Add("scope", "metaverse:read metaverse:write openid profile").
				Add("audience", "snowcrash").
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

func TestTokenRefreshToken(t *testing.T) {
	tests := map[string]litmus.Test{
		"TokenRefreshTokenOK": {
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
					Name:    "AuthorizedGrantTypes",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{testGrantTypes},
				},
				{
					Name:    "AuthCodeDestroy",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{nil},
				},
				{
					Name:    "AuthCodeCreate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("*oauth.AuthCode")},
					Returns: litmus.Returns{nil},
				},
				{
					Name:    "UserGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testUser, testPrin, nil},
				},
				{
					Name: "AuthCodeGet",
					Args: litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{&oauth.AuthCode{
						AuthRequest:       *testRequest,
						Code:              "00000000-0000-0000-0000-000000000000",
						IssuedAt:          time.Now().Unix(),
						SessionID:         "00000000-0000-0000-0000-000000000000",
						Subject:           "00000000-0000-0000-0000-000000000000",
						UserAuthenticated: true,
						RefreshNonce:      challenge,
					}, nil},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/token",
			ExpectedStatus:     http.StatusOK,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("grant_type", oauth.GrantTypeRefreshToken).
				Add("client_id", testApp.ClientID).
				Add("audience", "snowcrash").
				Add("refresh_token", challenge).
				Add("refresh_verifier", verifier).
				Add("refresh_nonce", verifier).
				Encode(),
		},
		"TokenRefreshTokenMissingToken": {
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
					Name:    "AuthorizedGrantTypes",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{testGrantTypes},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/token",
			ExpectedStatus:     http.StatusBadRequest,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("grant_type", oauth.GrantTypeRefreshToken).
				Add("client_id", testApp.ClientID).
				Add("audience", "snowcrash").
				Add("refresh_nonce", verifier).
				Encode(),
		},
		"TokenRefreshTokenNoAuthCode": {
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
					Name:    "AuthorizedGrantTypes",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{testGrantTypes},
				},
				{
					Name:    "AuthCodeGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{nil, errors.New("authcode node found")},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/token",
			ExpectedStatus:     http.StatusUnauthorized,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("grant_type", oauth.GrantTypeRefreshToken).
				Add("client_id", testApp.ClientID).
				Add("audience", "snowcrash").
				Add("refresh_token", challenge).
				Add("refresh_verifier", verifier).
				Add("refresh_nonce", verifier).
				Encode(),
		},
		"TokenRefreshTokenBadVerifier": {
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
					Name:    "AuthorizedGrantTypes",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{testGrantTypes},
				},
				{
					Name: "AuthCodeGet",
					Args: litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{&oauth.AuthCode{
						AuthRequest:       *testRequest,
						Code:              "00000000-0000-0000-0000-000000000000",
						IssuedAt:          time.Now().Unix(),
						SessionID:         "00000000-0000-0000-0000-000000000000",
						Subject:           "00000000-0000-0000-0000-000000000000",
						UserAuthenticated: true,
						RefreshNonce:      challenge,
					}, nil},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/token",
			ExpectedStatus:     http.StatusBadRequest,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("grant_type", oauth.GrantTypeRefreshToken).
				Add("client_id", testApp.ClientID).
				Add("audience", "snowcrash").
				Add("refresh_token", challenge).
				Add("refresh_verifier", "bad verifier").
				Add("refresh_nonce", verifier).
				Encode(),
		},
		"TokenRefreshTokenNonceMismatch": {
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
					Name:    "AuthorizedGrantTypes",
					Args:    litmus.Args{litmus.Context},
					Returns: litmus.Returns{testGrantTypes},
				},
				{
					Name:    "AuthCodeGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testCode, nil},
				},
			},
			Method:             http.MethodPost,
			Path:               "/oauth/token",
			ExpectedStatus:     http.StatusUnauthorized,
			RequestContentType: "application/x-www-form-urlencoded",
			Request: litmus.BeginQuery().
				Add("grant_type", oauth.GrantTypeRefreshToken).
				Add("client_id", testApp.ClientID).
				Add("audience", "snowcrash").
				Add("refresh_token", challenge).
				Add("refresh_verifier", verifier).
				Add("refresh_nonce", verifier).
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
