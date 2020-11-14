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
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string"), mock.AnythingOfType("*oauth.Profile")},
					Returns: litmus.Returns{nil},
				},
			},
			Method:             http.MethodPut,
			Path:               "/oauth/userInfo",
			ExpectedStatus:     http.StatusNoContent,
			RequestContentType: "application/json",
			Request:            testUser.Profile,
			Setup: func(r *http.Request) {
				auth.Handler(func(r *http.Request) (context.Context, error) {
					return oauth.NewContext(
						r.Context(),
						oauth.Context{
							User: testUser,
						}), nil
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
				auth.Handler(func(r *http.Request) (context.Context, error) {
					return oauth.NewContext(
						r.Context(),
						oauth.Context{
							User: nil,
						}), nil
				})
			},
		},
		"UserInfoUpdateError": {
			Operations: []litmus.Operation{
				{
					Name:    "UserUpdate",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("string"), mock.AnythingOfType("*oauth.Profile")},
					Returns: litmus.Returns{errors.New("access denied")},
				},
			},
			Method:             http.MethodPut,
			Path:               "/oauth/userInfo",
			ExpectedStatus:     http.StatusInternalServerError,
			RequestContentType: "application/json",
			Request:            testUser.Profile,
			Setup: func(r *http.Request) {
				auth.Handler(func(r *http.Request) (context.Context, error) {
					return oauth.NewContext(
						r.Context(),
						oauth.Context{
							User: testUser,
						}), nil
				})
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := new(mockController)

			mockServer := New(ctrl, api.WithLog(log.Log), WithAuthorizer(auth))

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
				auth.Handler(func(r *http.Request) (context.Context, error) {
					return oauth.NewContext(
						r.Context(),
						oauth.Context{
							User: testUser,
						}), nil
				})
			},
		},
		"UserInfoBadUser": {
			Operations:     []litmus.Operation{},
			Method:         http.MethodGet,
			Path:           "/oauth/userInfo",
			ExpectedStatus: http.StatusUnauthorized,
			Setup: func(r *http.Request) {
				auth.Handler(func(r *http.Request) (context.Context, error) {
					return oauth.NewContext(
						r.Context(),
						oauth.Context{
							User: nil,
						}), nil
				})
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := new(mockController)

			mockServer := New(ctrl, api.WithLog(log.Log), WithAuthorizer(auth))

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
				auth.Handler(func(r *http.Request) (context.Context, error) {
					return oauth.NewContext(
						r.Context(),
						oauth.Context{
							User:      testUser,
							Principal: testUser,
						}), nil
				})
			},
		},
		"UserPrincipalBadPrin": {
			Operations:     []litmus.Operation{},
			Method:         http.MethodGet,
			Path:           "/oauth/userPrincipal",
			ExpectedStatus: http.StatusUnauthorized,
			Setup: func(r *http.Request) {
				auth.Handler(func(r *http.Request) (context.Context, error) {
					return oauth.NewContext(
						r.Context(),
						oauth.Context{
							User: testUser,
						}), nil
				})
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := new(mockController)

			mockServer := New(ctrl, api.WithLog(log.Log), WithAuthorizer(auth))

			test.Do(&ctrl.Mock, mockServer, t)
		})
	}
}
