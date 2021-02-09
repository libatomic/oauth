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
	"time"

	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/litmus/pkg/litmus"
	"github.com/libatomic/oauth/pkg/oauth"
	"github.com/stretchr/testify/mock"
)

func TestTokenAuthcode(t *testing.T) {
	badChallenge := "not a challenge"

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
				{
					Name:    "TokenFinalize",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("oauth.Claims")},
					Returns: litmus.Returns{"", nil},
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
						PasswordExpiresAt: time.Now().Add(time.Hour),
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
					Returns: litmus.Returns{&mockAudience{
						name:           "snowcrash",
						permissions:    oauth.Permissions{"metaverse:read", "metaverse:write", "openid", "profile", "offline_access"},
						tokenAlgorithm: "RS256",
						tokenLifetime:  60,
					}, nil},
				},

				{
					Name:    "TokenFinalize",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("oauth.Claims")},
					Returns: litmus.Returns{"", nil},
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
					Returns: litmus.Returns{&mockAudience{
						name:           "snowcrash",
						permissions:    oauth.Permissions{"metaverse:read", "metaverse:write", "openid", "profile", "offline_access"},
						tokenAlgorithm: "RS256",
						tokenLifetime:  60,
					}, nil},
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
					Name:    "TokenFinalize",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("oauth.Claims")},
					Returns: litmus.Returns{"error", errors.New("bad key")},
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
					Name:    "AuthCodeGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testCode, nil},
				},
				{
					Name:    "ApplicationGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{nil, oauth.ErrApplicationNotFound},
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
					Name:    "AuthCodeGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testCode, nil},
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
					Name:    "AuthCodeGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testCode, nil},
				},
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testAud, nil},
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
					Name:    "AuthCodeGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{nil, oauth.ErrCodeNotFound},
				},
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testAud, nil},
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
					Name: "AuthCodeGet",
					Args: litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{&oauth.AuthCode{
						AuthRequest: oauth.AuthRequest{
							ClientID:            "00000000-0000-0000-0000-000000000000",
							RedirectURI:         mockURI,
							Scope:               oauth.Permissions{"metaverse:read", "metaverse:write", "openid", "profile", "offline_access"},
							Audience:            "snowcrash",
							CodeChallenge:       &badChallenge,
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
			ctrl := new(MockController)

			mockServer := New(ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl))

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
					Name:    "UserAuthenticate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string"), mock.AnythingOfType("string")},
					Returns: litmus.Returns{testUser, testPrin, nil},
				},
				{
					Name:    "TokenFinalize",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("oauth.Claims")},
					Returns: litmus.Returns{"", nil},
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
			ctrl := new(MockController)

			mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl), WithAllowedGrants(oauth.Permissions{
				oauth.GrantTypeAuthCode,
				oauth.GrantTypeClientCredentials,
				oauth.GrantTypeRefreshToken,
				oauth.GrantTypePassword,
			}))

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
					Name:    "TokenFinalize",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("oauth.Claims")},
					Returns: litmus.Returns{"", nil},
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
					Returns: litmus.Returns{&mockAudience{
						name:           "snowcrash",
						permissions:    oauth.Permissions{"metaverse:read", "metaverse:write", "openid", "profile", "offline_access"},
						tokenAlgorithm: "RS256",
						tokenLifetime:  60,
					}, nil},
				},
				{
					Name:    "TokenFinalize",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("oauth.Claims")},
					Returns: litmus.Returns{"error", errors.New("bad token")},
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
			ctrl := new(MockController)

			mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl))

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
				{
					Name:    "TokenFinalize",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("oauth.Claims")},
					Returns: litmus.Returns{"", nil},
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
				Add("code_verifier", verifier).
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
			ExpectedStatus:     http.StatusUnauthorized,
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
			ctrl := new(MockController)

			mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl))

			test.Do(&ctrl.Mock, mockServer, t)
		})
	}
}
