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

func TestUserInfoUpdate(t *testing.T) {
	auth := new(mockAuthorizer)

	tests := map[string]litmus.Test{
		"UserInfoUpdateOK": {
			Operations: []litmus.Operation{
				{
					Name:    "UserUpdate",
					Args:    litmus.Args{mock.AnythingOfType("*oauth.authContext"), mock.AnythingOfType("*oauth.User")},
					Returns: litmus.Returns{nil},
				},
			},
			Method:             http.MethodPut,
			Path:               "/oauth/userInfo",
			ExpectedStatus:     http.StatusOK,
			RequestContentType: "application/json",
			Request:            testUser.Profile,
			Setup: func(r *http.Request) {
				auth.Handler(func(r *http.Request) (interface{}, error) {
					return oauth.NewContext(
						r.Context(),
						oauth.WithUser(testUser),
					), nil
				})
			},
		},
		"UserInfoUpdateoBadUser": {
			Operations:         []litmus.Operation{},
			Method:             http.MethodPut,
			Path:               "/oauth/userInfo",
			ExpectedStatus:     http.StatusUnauthorized,
			RequestContentType: "application/json",
			Request:            testUser.Profile,
			Setup: func(r *http.Request) {
				auth.Handler(func(r *http.Request) (interface{}, error) {
					return oauth.NewContext(
						r.Context(),
						oauth.WithUser(nil),
					), nil
				})
			},
		},
		"UserInfoUpdateError": {
			Operations: []litmus.Operation{
				{
					Name:    "UserUpdate",
					Args:    litmus.Args{mock.AnythingOfType("*oauth.authContext"), mock.AnythingOfType("*oauth.User")},
					Returns: litmus.Returns{errors.New("access denied")},
				},
			},
			Method:             http.MethodPut,
			Path:               "/oauth/userInfo",
			ExpectedStatus:     http.StatusInternalServerError,
			RequestContentType: "application/json",
			Request:            testUser.Profile,
			Setup: func(r *http.Request) {
				auth.Handler(func(r *http.Request) (interface{}, error) {
					return oauth.NewContext(
						r.Context(),
						oauth.WithUser(testUser),
					), nil
				})
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := new(mockController)

			mockServer := New(ctrl, auth, api.WithLog(log.Log))

			test.Do(&ctrl.Mock, mockServer, t)
		})
	}
}

func TestUserInfo(t *testing.T) {
	auth := new(mockAuthorizer)

	tests := map[string]litmus.Test{
		"UserInfoOK": {
			Operations:     []litmus.Operation{},
			Method:         http.MethodGet,
			Path:           "/oauth/userInfo",
			ExpectedStatus: http.StatusOK,
			Setup: func(r *http.Request) {
				auth.Handler(func(r *http.Request) (interface{}, error) {
					return oauth.NewContext(
						r.Context(),
						oauth.WithUser(testUser),
					), nil
				})
			},
		},
		"UserInfoBadUser": {
			Operations:     []litmus.Operation{},
			Method:         http.MethodGet,
			Path:           "/oauth/userInfo",
			ExpectedStatus: http.StatusUnauthorized,
			Setup: func(r *http.Request) {
				auth.Handler(func(r *http.Request) (interface{}, error) {
					return oauth.NewContext(
						r.Context(),
						oauth.WithUser(nil),
					), nil
				})
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := new(mockController)

			mockServer := New(ctrl, auth, api.WithLog(log.Log))

			test.Do(&ctrl.Mock, mockServer, t)
		})
	}
}

func TestUserPrincipal(t *testing.T) {
	auth := new(mockAuthorizer)

	tests := map[string]litmus.Test{
		"UserPrincipalOK": {
			Operations:     []litmus.Operation{},
			Method:         http.MethodGet,
			Path:           "/oauth/userPrincipal",
			ExpectedStatus: http.StatusOK,
			Setup: func(r *http.Request) {
				auth.Handler(func(r *http.Request) (interface{}, error) {
					return oauth.NewContext(
						r.Context(),
						oauth.WithPrincipal(testUser),
					), nil
				})
			},
		},
		"UserPrincipalBadPrin": {
			Operations:     []litmus.Operation{},
			Method:         http.MethodGet,
			Path:           "/oauth/userPrincipal",
			ExpectedStatus: http.StatusUnauthorized,
			Setup: func(r *http.Request) {
				auth.Handler(func(r *http.Request) (interface{}, error) {
					return oauth.NewContext(
						r.Context(),
						oauth.WithUser(testUser),
					), nil
				})
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := new(mockController)

			mockServer := New(ctrl, auth, api.WithLog(log.Log))

			test.Do(&ctrl.Mock, mockServer, t)
		})
	}
}
