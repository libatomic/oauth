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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/google/uuid"
	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/oauth/pkg/oauth"
	"github.com/stretchr/testify/mock"
)

type (
	mockController struct {
		mock.Mock
	}

	mockAuthorizer struct {
		handler api.Authorizer
	}

	mockSession struct {
		id        string
		aud       string
		sub       string
		clientID  string
		createdAt int64
		expiresAt int64
	}
)

const (
	mockURI = "https://meta.org/"
)

var (
	verifier  string
	challenge string

	testAud = &oauth.Audience{
		Name:           "snowcrash",
		Permissions:    oauth.Permissions{"metaverse:read", "metaverse:write", "openid", "profile", "offline_access"},
		TokenAlgorithm: "HS256",
		TokenSecret:    "super-duper-secret",
		TokenLifetime:  60,
	}

	testApp = &oauth.Application{
		ClientID:     "00000000-0000-0000-0000-000000000000",
		ClientSecret: "super-secret",
		Permissions: oauth.PermissionSet{
			"snowcrash": oauth.Permissions{
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
	}

	testSession = &mockSession{
		clientID:  "00000000-0000-0000-0000-000000000000",
		aud:       testAud.Name,
		createdAt: time.Now().Unix(),
		expiresAt: time.Now().Add(time.Hour).Unix(),
		id:        "00000000-0000-0000-0000-000000000000",
		sub:       "00000000-0000-0000-0000-000000000000",
	}

	testUser = &oauth.User{
		Login:             "hiro@metaverse.org",
		PasswordExpiresAt: strfmt.DateTime(time.Now().Add(time.Hour)),
		Permissions: oauth.PermissionSet{
			"snowcrash": oauth.Permissions{"metaverse:read", "metaverse:write", "openid", "profile", "offline_access"},
		},
		Profile: &oauth.Profile{
			Subject:    uuid.Must(uuid.NewRandom()).String(),
			GivenName:  "Hiro",
			FamilyName: "Protagonist",
		},
	}

	testGrantTypes = oauth.Permissions{
		oauth.GrantTypePassword,
		oauth.GrantTypeAuthCode,
		oauth.GrantTypeClientCredentials,
		oauth.GrantTypeRefreshToken,
	}

	testPrin = &struct {
		oauth.User
		SecretPower string
	}{
		User:        *testUser,
		SecretPower: "blades of death",
	}

	testRequest *oauth.AuthRequest

	emptyScopeReq oauth.AuthRequest

	testCode *oauth.AuthCode

	testToken string

	expiredToken string

	badToken string

	misMatchToken string

	emptyScopeToken string

	testKey *rsa.PrivateKey
)

func init() {
	var err error

	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		panic(err)
	}

	verifier = base64.RawURLEncoding.EncodeToString(token)

	sum := sha256.Sum256(token)

	challenge = base64.RawURLEncoding.EncodeToString(sum[:])

	testKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	err = testKey.Validate()
	if err != nil {
		panic(err)
	}

	state := "foo"

	testRequest = &oauth.AuthRequest{
		ClientID:            "00000000-0000-0000-0000-000000000000",
		RedirectURI:         mockURI,
		Scope:               oauth.Permissions{"metaverse:read", "metaverse:write", "openid", "profile", "offline_access"},
		Audience:            "snowcrash",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(time.Minute * 10).Unix(),
		State:               &state,
	}

	testCode = &oauth.AuthCode{
		AuthRequest:       *testRequest,
		Code:              "00000000-0000-0000-0000-000000000000",
		IssuedAt:          time.Now().Unix(),
		SessionID:         "00000000-0000-0000-0000-000000000000",
		Subject:           "00000000-0000-0000-0000-000000000000",
		UserAuthenticated: true,
	}

	testToken, err = signValue(context.TODO(), testKey, AuthRequestParam, testRequest)
	if err != nil {
		panic(err)
	}

	expiredReq := *testRequest
	expiredReq.ExpiresAt = time.Now().Add(time.Minute * -10).Unix()

	expiredToken, err = signValue(context.TODO(), testKey, AuthRequestParam, expiredReq)
	if err != nil {
		panic(err)
	}

	badReq := *testRequest
	badReq.CodeChallenge += "bad stuff"

	badToken, err = signValue(context.TODO(), testKey, AuthRequestParam, badReq)
	if err != nil {
		panic(err)
	}

	token = make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		panic(err)
	}

	misSum := sha256.Sum256(token)

	misChal := base64.RawURLEncoding.EncodeToString(misSum[:])

	misMatchReq := *testRequest
	misMatchReq.CodeChallenge = misChal

	misMatchToken, err = signValue(context.TODO(), testKey, AuthRequestParam, misMatchReq)
	if err != nil {
		panic(err)
	}

	emptyScopeReq = *testRequest
	emptyScopeReq.Scope = oauth.Permissions{}

	emptyScopeToken, err = signValue(context.TODO(), testKey, AuthRequestParam, emptyScopeReq)
	if err != nil {
		panic(err)
	}
}

func (c *mockController) ApplicationGet(ctx context.Context, id string) (*oauth.Application, error) {
	args := c.Called(ctx, id)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*oauth.Application), args.Error(1)
}

func (c *mockController) AudienceGet(ctx context.Context, name string) (*oauth.Audience, error) {
	args := c.Called(ctx, name)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*oauth.Audience), args.Error(1)
}

func (c *mockController) UserGet(ctx context.Context, login string) (*oauth.User, interface{}, error) {
	args := c.Called(ctx, login)

	if args.Get(0) == nil {
		return nil, args.Get(1), args.Error(2)
	}

	return args.Get(0).(*oauth.User), args.Get(1), args.Error(2)
}

func (c *mockController) UserAuthenticate(ctx context.Context, login string, password string) (*oauth.User, interface{}, error) {
	args := c.Called(ctx, login, password)

	if args.Get(0) == nil {
		return nil, args.Get(1), args.Error(2)
	}

	return args.Get(0).(*oauth.User), args.Get(1), args.Error(2)
}

func (c *mockController) UserCreate(ctx context.Context, user oauth.User, password string, invite ...string) (*oauth.User, error) {
	args := c.Called(ctx, user, password)

	user.Profile.Subject = "00000000-0000-0000-0000-000000000000"

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*oauth.User), args.Error(1)
}

func (c *mockController) UserVerify(ctx context.Context, id string, code string) error {
	return nil
}

func (c *mockController) UserUpdate(ctx context.Context, user *oauth.User) error {
	args := c.Called(ctx, user)

	return args.Error(0)
}

func (c *mockController) UserResetPassword(ctx context.Context, login string, resetCode string) error {
	return nil
}

func (c *mockController) UserSetPassword(ctx context.Context, id string, password string) error {
	return nil
}

func (c *mockController) TokenFinalize(ctx context.Context, scope oauth.Permissions, claims map[string]interface{}) {

}

func (c *mockController) TokenPrivateKey(ctx context.Context) (*rsa.PrivateKey, error) {
	args := c.Called(ctx)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*rsa.PrivateKey), args.Error(1)
}

func (c *mockController) TokenPublicKey(ctx context.Context) (*rsa.PublicKey, error) {
	args := c.Called(ctx)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*rsa.PublicKey), args.Error(1)
}

// AuthCodeCreate creates a new authcode from the request if code expires at is set
// the store should use that value, otherwise set the defaults
func (c *mockController) AuthCodeCreate(ctx context.Context, code *oauth.AuthCode) error {
	args := c.Called(ctx, code)

	if code != nil {
		code.Code = "00000000-0000-0000-0000-000000000000"
	}

	return args.Error(0)
}

// AuthCodeGet returns a code from the store
func (c *mockController) AuthCodeGet(ctx context.Context, id string) (*oauth.AuthCode, error) {
	args := c.Called(ctx, id)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*oauth.AuthCode), args.Error(1)
}

// AuthCodeDestroy removes a code from the store
func (c *mockController) AuthCodeDestroy(ctx context.Context, id string) error {
	args := c.Called(ctx, id)

	return args.Error(0)
}

// SessionCreate creates a session
func (c *mockController) SessionCreate(ctx context.Context, r *http.Request) (oauth.Session, error) {
	args := c.Called(ctx, r)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(oauth.Session), args.Error(1)
}

// SessionRead retrieves the session from the request
func (c *mockController) SessionRead(ctx context.Context, r *http.Request) (oauth.Session, error) {
	args := c.Called(ctx, r)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(oauth.Session), args.Error(1)
}

// SessionDestroy destroys the session in the response
func (c *mockController) SessionDestroy(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	args := c.Called(ctx, w, r)

	return args.Error(0)
}

func (c *mockController) Authorize(opts ...oauth.AuthOption) api.Authorizer {
	return func(r *http.Request) (context.Context, error) {
		return context.TODO(), nil
	}
}

func (c *mockAuthorizer) Authorize(opts ...oauth.AuthOption) api.Authorizer {
	return func(r *http.Request) (context.Context, error) {
		return c.handler(r)
	}
}

func (c *mockAuthorizer) Handler(h api.Authorizer) {
	c.handler = h
}

// ID is the session id
func (s *mockSession) ID() string {
	return s.id
}

// ClientID is the client that created the user session
func (s *mockSession) ClientID() string {
	return s.clientID
}

// Audience is the audiene the session was for
func (s *mockSession) Audience() string {
	return s.aud
}

// CreatedAt is the session creation time
func (s *mockSession) CreatedAt() time.Time {
	return time.Unix(s.createdAt, 0)
}

// ExpiresAt is the session expriation time
func (s *mockSession) ExpiresAt() time.Time {
	return time.Unix(s.expiresAt, 0)
}

// Subject is the user subject id
func (s *mockSession) Subject() string {
	return s.sub
}

// Set sets a value in the session interface
func (s *mockSession) Set(key string, value interface{}) {

}

// Get gets a value from the session interface
func (s *mockSession) Get(key string) interface{} {
	return struct{}{}
}

// Write writes the session to the response
func (s *mockSession) Write(http.ResponseWriter) error {
	return nil
}

// Destroy clears the session from the response
func (s *mockSession) Destroy(http.ResponseWriter) error {
	return nil
}
