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

	"github.com/apex/log"
	"github.com/fatih/structs"
	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/litmus/pkg/litmus"
	"github.com/libatomic/oauth/pkg/oauth"
	"github.com/stretchr/testify/mock"
)

func TestVerifySend(t *testing.T) {
	auth := new(MockAuthorizer)

	tests := map[string]litmus.Test{
		"VerifySend": {
			Operations: []litmus.Operation{
				{
					Name:    "TokenFinalize",
					Args:    litmus.Args{litmus.Context, mock.AnythingOfType("oauth.Claims")},
					Returns: litmus.Returns{"", nil},
				},
			},
			Method: http.MethodPost,
			Path:   "/oauth/verify",
			Request: &VerifySendParams{
				Method: oauth.NotificationChannelEmail,
			},
			ExpectedStatus:     http.StatusNoContent,
			RequestContentType: "application/json",
			Setup: func(r *http.Request) {
				auth.Handler(func(r *http.Request) (context.Context, error) {
					return oauth.NewContext(
						r.Context(),
						oauth.Context{
							Application: testApp,
							Audience:    testAud,
							User:        testUser,
							Principal:   testPrin,
						}), nil
				})
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := new(MockController)

			mockServer := New(ctrl, api.WithLog(log.Log), WithAuthorizer(auth))

			test.Do(&ctrl.Mock, mockServer, t)
		})
	}
}

func TestVerify(t *testing.T) {
	auth := new(MockAuthorizer)

	tests := map[string]litmus.Test{
		"Verify": {
			Method: http.MethodGet,
			Path:   "/oauth/verify",
			Request: &VerifyParams{
				RedirectURI: testRequest.RedirectURI,
			},
			ExpectedStatus: http.StatusFound,
			ExpectedHeaders: map[string]string{
				"Location": `https:\/\/meta\.org\/`,
			},
			RequestContentType: "application/json",
			Setup: func(r *http.Request) {
				auth.Handler(func(r *http.Request) (context.Context, error) {
					return oauth.NewContext(
						r.Context(),
						oauth.Context{
							Application: testApp,
							Audience:    testAud,
							User:        testUser,
							Principal:   testPrin,
							Token:       oauth.Claims(structs.Map(testRequest)),
						}), nil
				})
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := new(MockController)

			mockServer := New(ctrl, api.WithLog(log.Log), WithAuthorizer(auth))

			test.Do(&ctrl.Mock, mockServer, t)
		})
	}
}
