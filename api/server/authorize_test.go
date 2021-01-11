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
	"github.com/google/uuid"
	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/litmus/pkg/litmus"
	"github.com/libatomic/oauth/pkg/oauth"
	"github.com/stretchr/testify/mock"
)

func TestAuthorize(t *testing.T) {
	tests := map[string]litmus.Test{
		"AuthorizeOK": {
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
					Name:    "SessionRead",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("*http.Request")},
					Returns: litmus.Returns{nil, oauth.ErrSessionNotFound},
				},
				{
					Name:    "TokenFinalize",
					Args:    litmus.Args{litmus.Context, oauth.Claims{}},
					Returns: litmus.Returns{testToken, nil},
				},
			},
			Method: http.MethodGet,
			Path:   "/oauth/authorize",
			Query: litmus.BeginQuery().
				Add("response_type", "code").
				Add("client_id", uuid.Must(uuid.NewRandom()).String()).
				Add("audience", "snowcrash").
				Add("scope", "metaverse:read metaverse:write openid profile offline_access").
				Add("code_challenge", challenge).
				EndQuery(),
			ExpectedStatus: http.StatusFound,
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/\?request_token=.?`,
			},
		},
		"AuthorizeExistingSession": {
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
					Name:    "SessionRead",
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
			Path:   "/oauth/authorize",
			Query: litmus.BeginQuery().
				Add("response_type", "code").
				Add("client_id", uuid.Must(uuid.NewRandom()).String()).
				Add("audience", "snowcrash").
				Add("app_uri", mockURI).
				Add("redirect_uri", mockURI).
				Add("state", "foo").
				Add("scope", "metaverse:read metaverse:write openid profile offline_access").
				Add("code_challenge", challenge).
				EndQuery(),
			ExpectedStatus: http.StatusFound,
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/\?code=00000000-0000-0000-0000-000000000000&state=foo`,
			},
		},
		"AuthorizeAppGetError": {
			Operations: []litmus.Operation{
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testAud, nil},
				},
				{
					Name:    "ApplicationGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{nil, oauth.ErrApplicationNotFound},
				},
			},
			Method: http.MethodGet,
			Path:   "/oauth/authorize",
			Query: litmus.BeginQuery().
				Add("response_type", "code").
				Add("client_id", uuid.Must(uuid.NewRandom()).String()).
				Add("audience", "snowcrash").
				Add("app_uri", mockURI).
				Add("redirect_uri", mockURI).
				Add("scope", "metaverse:read metaverse:write openid profile offline_access").
				Add("code_challenge", challenge).
				EndQuery(),
			ExpectedStatus: http.StatusBadRequest,
		},
		"AuthorizeAudGetError": {
			Operations: []litmus.Operation{
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{nil, oauth.ErrAudienceNotFound},
				},
			},
			Method: http.MethodGet,
			Path:   "/oauth/authorize",
			Query: litmus.BeginQuery().
				Add("response_type", "code").
				Add("client_id", uuid.Must(uuid.NewRandom()).String()).
				Add("audience", "snowcrash").
				Add("app_uri", mockURI).
				Add("redirect_uri", mockURI).
				Add("scope", "metaverse:read metaverse:write openid profile offline_access").
				Add("code_challenge", challenge).
				EndQuery(),
			ExpectedStatus: http.StatusBadRequest,
		},
		"AuthorizeBadGrant": {
			Operations: []litmus.Operation{
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testAud, nil},
				},
				{
					Name: "ApplicationGet",
					Args: litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{
						&oauth.Application{}, nil},
				},
			},
			Method: http.MethodGet,
			Path:   "/oauth/authorize",
			Query: litmus.BeginQuery().
				Add("response_type", "code").
				Add("client_id", uuid.Must(uuid.NewRandom()).String()).
				Add("audience", "snowcrash").
				Add("scope", "metaverse:read metaverse:write openid profile offline_access").
				Add("code_challenge", challenge).
				EndQuery(),
			ExpectedStatus: http.StatusUnauthorized,
		},
		"AuthorizeBadRedirectURI": {
			Operations: []litmus.Operation{
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testAud, nil},
				},
				{
					Name: "ApplicationGet",
					Args: litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{
						&oauth.Application{
							AllowedGrants: oauth.PermissionSet{
								testAud.name: oauth.Permissions{oauth.GrantTypeAuthCode},
							},
							RedirectUris: oauth.PermissionSet{
								testAud.name: oauth.Permissions{"http://foo"},
							},
						}, nil},
				},
			},
			Method: http.MethodGet,
			Path:   "/oauth/authorize",
			Query: litmus.BeginQuery().
				Add("response_type", "code").
				Add("client_id", uuid.Must(uuid.NewRandom()).String()).
				Add("audience", "snowcrash").
				Add("redirect_uri", mockURI).
				Add("scope", "metaverse:read metaverse:write openid profile offline_access").
				Add("code_challenge", challenge).
				EndQuery(),
			ExpectedStatus: http.StatusUnauthorized,
		},
		"AuthorizeBadAppURI": {
			Operations: []litmus.Operation{
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testAud, nil},
				},
				{
					Name: "ApplicationGet",
					Args: litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{
						&oauth.Application{
							AllowedGrants: oauth.PermissionSet{
								testAud.name: oauth.Permissions{oauth.GrantTypeAuthCode},
							},
							AppUris: oauth.PermissionSet{
								testAud.name: oauth.Permissions{"http://foo"},
							},
							RedirectUris: oauth.PermissionSet{
								testAud.name: oauth.Permissions{mockURI},
							},
						}, nil},
				},
			},
			Method: http.MethodGet,
			Path:   "/oauth/authorize",
			Query: litmus.BeginQuery().
				Add("response_type", "code").
				Add("client_id", uuid.Must(uuid.NewRandom()).String()).
				Add("audience", "snowcrash").
				Add("redirect_uri", mockURI).
				Add("app_uri", mockURI).
				Add("scope", "metaverse:read metaverse:write openid profile offline_access").
				Add("code_challenge", challenge).
				EndQuery(),
			ExpectedStatus: http.StatusFound,
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/\?error=access_denied&error_description=unauthorized\+uri`,
			},
		},
		"AuthorizeBadAppScope": {
			Operations: []litmus.Operation{
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testAud, nil},
				},
				{
					Name: "ApplicationGet",
					Args: litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{
						&oauth.Application{
							Permissions: oauth.PermissionSet{
								"cryptonomicon": oauth.Permissions{
									"metaverse:read", "metaverse:write", "openid", "profile", "offline_access"},
							},
							AllowedGrants: oauth.PermissionSet{
								testAud.name: oauth.Permissions{oauth.GrantTypeAuthCode},
							},
							AppUris: oauth.PermissionSet{
								testAud.name: oauth.Permissions{mockURI},
							},
							RedirectUris: oauth.PermissionSet{
								testAud.name: oauth.Permissions{mockURI},
							},
						}, nil},
				},
			},
			Method: http.MethodGet,
			Path:   "/oauth/authorize",
			Query: litmus.BeginQuery().
				Add("response_type", "code").
				Add("client_id", uuid.Must(uuid.NewRandom()).String()).
				Add("audience", "snowcrash").
				Add("redirect_uri", mockURI).
				Add("app_uri", mockURI).
				Add("scope", "metaverse:read metaverse:write openid profile offline_access").
				Add("code_challenge", challenge).
				EndQuery(),
			ExpectedStatus: http.StatusFound,
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/\?error=access_denied&error_description=invalid\+audience`,
			},
		},
		"AuthorizeBadAudScope": {
			Operations: []litmus.Operation{
				{
					Name: "AudienceGet",
					Args: litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{&mockAudience{
						name:           "snowcrash",
						permissions:    oauth.Permissions{"metaverse:destroy"},
						tokenAlgorithm: "HS256",
						tokenSecret:    "super-duper-secret",
						tokenLifetime:  60,
					}, nil},
				},
				{
					Name:    "ApplicationGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testApp, nil},
				},
			},
			Method: http.MethodGet,
			Path:   "/oauth/authorize",
			Query: litmus.BeginQuery().
				Add("response_type", "code").
				Add("client_id", uuid.Must(uuid.NewRandom()).String()).
				Add("audience", "snowcrash").
				Add("redirect_uri", mockURI).
				Add("app_uri", mockURI).
				Add("scope", "metaverse:read").
				Add("code_challenge", challenge).
				EndQuery(),
			ExpectedStatus: http.StatusFound,
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/\?error=access_denied&error_description=insufficient\+permissions`,
			},
		},
		"AuthorizeSessionReadError": {
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
					Name:    "SessionRead",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("*http.Request")},
					Returns: litmus.Returns{nil, errors.New("something bad")},
				},
			},
			Method: http.MethodGet,
			Path:   "/oauth/authorize",
			Query: litmus.BeginQuery().
				Add("response_type", "code").
				Add("client_id", uuid.Must(uuid.NewRandom()).String()).
				Add("audience", "snowcrash").
				Add("scope", "metaverse:read metaverse:write openid profile offline_access").
				Add("code_challenge", challenge).
				EndQuery(),
			ExpectedStatus: http.StatusFound,
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/\?error=server_error&error_description=something\+bad`,
			},
		},
		"AuthorizeAuthCodeCreateError": {
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
					Name:    "SessionRead",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("*http.Request")},
					Returns: litmus.Returns{testSession, nil},
				},
				{
					Name:    "AuthCodeCreate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("*oauth.AuthCode")},
					Returns: litmus.Returns{errors.New("something bad")},
				},
			},
			Method: http.MethodGet,
			Path:   "/oauth/authorize",
			Query: litmus.BeginQuery().
				Add("response_type", "code").
				Add("client_id", uuid.Must(uuid.NewRandom()).String()).
				Add("audience", "snowcrash").
				Add("app_uri", mockURI).
				Add("redirect_uri", mockURI).
				Add("state", "foo").
				Add("scope", "metaverse:read metaverse:write openid profile offline_access").
				Add("code_challenge", challenge).
				EndQuery(),
			ExpectedStatus: http.StatusFound,
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/\?error=server_error&error_description=something\+bad`,
			},
		},
		"AuthorizeRequestSignError": {
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
					Name:    "SessionRead",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("*http.Request")},
					Returns: litmus.Returns{nil, nil},
				},
				{
					Name:    "TokenFinalize",
					Args:    litmus.Args{litmus.Context, oauth.Claims{}},
					Returns: litmus.Returns{"none", errors.New("something bad")},
				},
			},
			Method: http.MethodGet,
			Path:   "/oauth/authorize",
			Query: litmus.BeginQuery().
				Add("response_type", "code").
				Add("client_id", uuid.Must(uuid.NewRandom()).String()).
				Add("audience", "snowcrash").
				Add("scope", "metaverse:read metaverse:write openid profile offline_access").
				Add("code_challenge", challenge).
				EndQuery(),
			ExpectedStatus: http.StatusFound,
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/\?error=server_error&error_description=something\+bad`,
			},
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
