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
					Name:    "SessionRead",
					Args:    litmus.Args{mock.AnythingOfType("*http.Request")},
					Returns: litmus.Returns{nil, oauth.ErrSessionNotFound},
				},
				{
					Name:    "TokenPrivateKey",
					Args:    litmus.Args{mock.AnythingOfType("*oauth.authContext")},
					Returns: litmus.Returns{testKey, nil},
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
					Name:    "SessionRead",
					Args:    litmus.Args{mock.AnythingOfType("*http.Request")},
					Returns: litmus.Returns{testSession, nil},
				},
				{
					Name:    "AuthCodeCreate",
					Args:    litmus.Args{mock.AnythingOfType("*oauth.authContext"), mock.AnythingOfType("*oauth.AuthCode")},
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
					Name:    "ApplicationGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testApp, nil},
				},
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
			ExpectedStatus: http.StatusFound,
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/\?error=bad_request&error_description=invalid\+audience`,
			},
		},
		"AuthorizeBadGrant": {
			Operations: []litmus.Operation{
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
					Name: "ApplicationGet",
					Args: litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{
						&oauth.Application{
							AllowedGrants: oauth.Permissions{
								oauth.GrantTypeAuthCode,
							},
							RedirectUris: oauth.Permissions{"http://foo"},
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
					Name: "ApplicationGet",
					Args: litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{
						&oauth.Application{
							AllowedGrants: oauth.Permissions{
								oauth.GrantTypeAuthCode,
							},
							AppUris:      oauth.Permissions{"http://foo"},
							RedirectUris: oauth.Permissions{mockURI},
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
				"Location": `https:\/\/meta\.org\/\?error=access_denied&error_description=unauthorized\+redirect\+uri`,
			},
		},
		"AuthorizeBadAppScope": {
			Operations: []litmus.Operation{
				{
					Name: "ApplicationGet",
					Args: litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{
						&oauth.Application{
							Permissions: oauth.PermissionSet{
								"cryptonomicon": oauth.Permissions{
									"metaverse:read", "metaverse:write", "openid", "profile", "offline_access"},
							},
							AllowedGrants: oauth.Permissions{
								oauth.GrantTypeAuthCode,
							},
							AppUris:      oauth.Permissions{mockURI},
							RedirectUris: oauth.Permissions{mockURI},
						}, nil},
				},
				{
					Name:    "AudienceGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testAud, nil},
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
					Name:    "ApplicationGet",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{testApp, nil},
				},
				{
					Name: "AudienceGet",
					Args: litmus.Args{litmus.Context, mock.AnythingOfType("string")},
					Returns: litmus.Returns{&oauth.Audience{
						Name:           "funky-chicken",
						Permissions:    oauth.Permissions{"metaverse:destroy"},
						TokenAlgorithm: "HS256",
						TokenSecret:    "super-duper-secret",
						TokenLifetime:  60,
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
					Name:    "SessionRead",
					Args:    litmus.Args{mock.AnythingOfType("*http.Request")},
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
					Name:    "SessionRead",
					Args:    litmus.Args{mock.AnythingOfType("*http.Request")},
					Returns: litmus.Returns{testSession, nil},
				},
				{
					Name:    "AuthCodeCreate",
					Args:    litmus.Args{mock.AnythingOfType("*oauth.authContext"), mock.AnythingOfType("*oauth.AuthCode")},
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
					Name:    "SessionRead",
					Args:    litmus.Args{mock.AnythingOfType("*http.Request")},
					Returns: litmus.Returns{nil, nil},
				},
				{
					Name:    "TokenPrivateKey",
					Args:    litmus.Args{mock.AnythingOfType("*oauth.authContext")},
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
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := new(mockController)

			mockServer := New(ctrl, ctrl, api.WithLog(log.Log))

			test.Do(&ctrl.Mock, mockServer, t)
		})
	}
}
