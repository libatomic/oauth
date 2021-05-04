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

func TestAuthorizeOK(t *testing.T) {
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
			Add("scope", "metaverse:read metaverse:write openid profile offline_access").
			Add("code_challenge", challenge).
			EndQuery(),
		ExpectedStatus: http.StatusFound,
		ExpectedHeaders: map[string]string{
			"Location": `https:\/\/meta\.org\/\?mode=password&request_token=.?`,
		},
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestAuthorizeErrTokenFinalize(t *testing.T) {
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
				Name:    "SessionRead",
				Args:    litmus.Args{litmus.Context, mock.AnythingOfType("*http.Request")},
				Returns: litmus.Returns{nil, oauth.ErrSessionNotFound},
			},
			{
				Name:    "TokenFinalize",
				Args:    litmus.Args{litmus.Context, oauth.Claims{}},
				Returns: litmus.Returns{nil, oauth.ErrInvalidToken},
			},
		},
		Method: http.MethodGet,
		Path:   "/oauth/authorize",
		Query: litmus.BeginQuery().
			Add("response_type", "code").
			Add("client_id", uuid.Must(uuid.NewRandom()).String()).
			Add("scope", "metaverse:read metaverse:write openid profile offline_access").
			Add("code_challenge", challenge).
			EndQuery(),
		ExpectedStatus: http.StatusFound,
		ExpectedHeaders: map[string]string{
			"Location": `https:\/\/meta\.org\/\?error=server_error&error_description=invalid\+token`,
		},
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestAuthorizeExistingSession(t *testing.T) {
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
				Name:    "SessionRead",
				Args:    litmus.Args{litmus.Context, mock.AnythingOfType("*http.Request")},
				Returns: litmus.Returns{testSession, nil},
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
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestAuthorizeErrAuthCodeCreate(t *testing.T) {
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
				Name:    "SessionRead",
				Args:    litmus.Args{litmus.Context, mock.AnythingOfType("*http.Request")},
				Returns: litmus.Returns{testSession, nil},
			},
			{
				Name:    "UserGet",
				Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
				Returns: litmus.Returns{testUser, testUser, nil},
			},
			{
				Name:    "AuthCodeCreate",
				Args:    litmus.Args{litmus.Context, mock.AnythingOfType("*oauth.AuthCode")},
				Returns: litmus.Returns{oauth.ErrInvalidToken},
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
			"Location": `https:\/\/meta\.org\/\?error=server_error&error_description=invalid\+token`,
		},
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestAuthorizeMissingParameter(t *testing.T) {
	test := litmus.Test{
		Operations: []litmus.Operation{},
		Method:     http.MethodGet,
		Path:       "/oauth/authorize",
		Query: litmus.BeginQuery().
			Add("response_type", "code").
			Add("scope", "metaverse:read metaverse:write openid profile offline_access").
			Add("code_challenge", challenge).
			EndQuery(),
		ExpectedStatus: http.StatusBadRequest,
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestAuthorizeErrAudNotFound(t *testing.T) {
	test := litmus.Test{
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
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestAuthorizeErrAppNotFound(t *testing.T) {
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
		ExpectedStatus: http.StatusUnauthorized,
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestAuthorizeErrMissingRedirectURI(t *testing.T) {
	test := litmus.Test{
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
						RedirectUris: oauth.PermissionSet{},
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
		ExpectedStatus: http.StatusBadRequest,
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestAuthorizeErrMissingAppURI(t *testing.T) {
	test := litmus.Test{
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
			Add("scope", "metaverse:read metaverse:write openid profile offline_access").
			Add("code_challenge", challenge).
			EndQuery(),
		ExpectedStatus: http.StatusFound,
		ExpectedHeaders: map[string]string{
			"Location": `https:\/\/meta\.org\/\?error=access_denied&error_description=application\+has\+no\+valid\+app\+uris`,
		},
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestAuthorizeErrInvalidAppURI(t *testing.T) {
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
		},
		Method: http.MethodGet,
		Path:   "/oauth/authorize",
		Query: litmus.BeginQuery().
			Add("response_type", "code").
			Add("client_id", uuid.Must(uuid.NewRandom()).String()).
			Add("audience", "snowcrash").
			Add("redirect_uri", mockURI).
			Add("app_uri", "https://foo").
			Add("scope", "metaverse:read metaverse:write openid profile offline_access").
			Add("code_challenge", challenge).
			EndQuery(),
		ExpectedStatus: http.StatusFound,
		ExpectedHeaders: map[string]string{
			"Location": `https:\/\/meta\.org\/\?error=access_denied&error_description=unauthorized\+uri`,
		},
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestAuthorizeErrUnauthorizedRedirect(t *testing.T) {
	test := litmus.Test{
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
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestAuthorizeErrUnauthorizedGrant(t *testing.T) {
	test := litmus.Test{
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
							testAud.name: oauth.Permissions{},
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
			Add("scope", "metaverse:read metaverse:write openid profile offline_access").
			Add("code_challenge", challenge).
			EndQuery(),
		ExpectedStatus: http.StatusFound,
		ExpectedHeaders: map[string]string{
			"Location": `https:\/\/meta\.org\/\?error=access_denied&error_description=unsupported\+grant`,
		},
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestAuthorizeErrInvalidSession(t *testing.T) {
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
				Name:    "SessionRead",
				Args:    litmus.Args{litmus.Context, mock.AnythingOfType("*http.Request")},
				Returns: litmus.Returns{nil, errors.New("invalid session")},
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
			"Location": `https:\/\/meta\.org\/\?error=server_error&error_description=invalid\+session`,
		},
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestAuthorizeErrSessionBadUser(t *testing.T) {
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
				Name:    "SessionRead",
				Args:    litmus.Args{litmus.Context, mock.AnythingOfType("*http.Request")},
				Returns: litmus.Returns{testSession, nil},
			},
			{
				Name:    "UserGet",
				Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string")},
				Returns: litmus.Returns{nil, nil, oauth.ErrUserNotFound},
			},
			{
				Name: "SessionDestroy",
				Args: litmus.Args{
					litmus.Context,
					mock.AnythingOfTypeArgument("*api.responseWriter"),
					mock.AnythingOfType("*http.Request")},
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
			"Location": `https:\/\/meta\.org\/\?error=access_denied&error_description=user\+not\+found`,
		},
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestAuthorizeErrBadAudScope(t *testing.T) {
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
		},
		Method: http.MethodGet,
		Path:   "/oauth/authorize",
		Query: litmus.BeginQuery().
			Add("response_type", "code").
			Add("client_id", uuid.Must(uuid.NewRandom()).String()).
			Add("audience", "snowcrash").
			Add("redirect_uri", mockURI).
			Add("scope", "yt").
			Add("code_challenge", challenge).
			EndQuery(),
		ExpectedStatus: http.StatusFound,
		ExpectedHeaders: map[string]string{
			"Location": `https:\/\/meta\.org\/\?error=access_denied&error_description=insufficient\+audience\+permissions`,
		},
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl))

	test.Do(&ctrl.Mock, mockServer, t)
}

func TestAuthorizeErrBadAppScope(t *testing.T) {
	testAud := *testAud

	testAud.permissions = append(testAud.permissions, "yt")

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
		},
		Method: http.MethodGet,
		Path:   "/oauth/authorize",
		Query: litmus.BeginQuery().
			Add("response_type", "code").
			Add("client_id", uuid.Must(uuid.NewRandom()).String()).
			Add("audience", "snowcrash").
			Add("redirect_uri", mockURI).
			Add("scope", "yt").
			Add("code_challenge", challenge).
			EndQuery(),
		ExpectedStatus: http.StatusFound,
		ExpectedHeaders: map[string]string{
			"Location": `https:\/\/meta\.org\/\?error=access_denied&error_description=invalid\+application\+scope`,
		},
	}

	ctrl := new(MockController)

	mockServer := New(ctrl, ctrl, api.WithLog(log.Log), WithCodeStore(ctrl), WithSessionStore(ctrl))

	test.Do(&ctrl.Mock, mockServer, t)
}
