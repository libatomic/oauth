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
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/fatih/structs"
	"github.com/imdario/mergo"
	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/litmus/pkg/litmus"
	"github.com/libatomic/oauth/pkg/oauth"
)

type (
	MockController struct {
		litmus.Mock
	}

	MockAuthorizer struct {
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

	mockAudience struct {
		name           string
		description    *string
		permissions    oauth.Permissions
		tokenAlgorithm string
		tokenLifetime  int64
		tokenSecret    string
		key            *rsa.PrivateKey
	}
)

const (
	mockURI = "https://meta.org/"
	altURI  = "https://meta.ord/foo"
)

var (
	verifier  string
	challenge string

	testAud = &mockAudience{
		name:           "snowcrash",
		permissions:    oauth.Permissions{"metaverse:read", "metaverse:write", "openid", "profile", "offline_access", "password", "email:verify"},
		tokenAlgorithm: "RS256",
		tokenLifetime:  60,
	}

	testApp = &oauth.Application{
		ClientID:     "00000000-0000-0000-0000-000000000000",
		ClientSecret: "super-secret",
		Permissions: oauth.PermissionSet{
			"snowcrash": oauth.Permissions{
				"metaverse:read", "metaverse:write", "openid", "profile", "offline_access", "password", "email:verify"},
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
			"snowcrash": oauth.Permissions{mockURI, altURI},
		},
		RedirectUris: oauth.PermissionSet{
			"snowcrash": oauth.Permissions{mockURI, altURI},
		},
		TokenLifetime: 60,
	}

	testSession = &mockSession{
		clientID:  "00000000-0000-0000-0000-000000000000",
		aud:       testAud.name,
		createdAt: time.Now().Unix(),
		expiresAt: time.Now().Add(time.Hour).Unix(),
		id:        "00000000-0000-0000-0000-000000000000",
		sub:       "00000000-0000-0000-0000-000000000000",
	}

	userEmail = "hiro@metaverse.org"
	userPhone = "555-1212"

	testUser = &oauth.User{
		Login:             "hiro@metaverse.org",
		PasswordExpiresAt: time.Now().Add(time.Hour),
		Permissions: oauth.PermissionSet{
			"snowcrash": oauth.Permissions{"metaverse:read", "metaverse:write", "openid", "profile", "offline_access", "password", "email:verify"},
		},
		Profile: &oauth.Profile{
			Subject:    "00000000-0000-0000-0000-000000000000",
			GivenName:  "Hiro",
			FamilyName: "Protagonist",
			Name:       "Hiro Protagonist",
			EmailClaim: &oauth.EmailClaim{
				Email: &userEmail,
			},
			PhoneClaim: &oauth.PhoneClaim{
				PhoneNumber: &userPhone,
			},
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

	expiredReq oauth.AuthRequest

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

	reader := rand.Reader
	key, err := rsa.GenerateKey(reader, 2048)
	if err != nil {
		panic(err)
	}
	testAud.key = key

	structs.DefaultTagName = "json"

	verifier = base64.RawURLEncoding.EncodeToString(token)

	sum := sha256.Sum256([]byte(verifier))

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

	sub := "00000000-0000-0000-0000-000000000000"

	testRequest = &oauth.AuthRequest{
		ClientID:            "00000000-0000-0000-0000-000000000000",
		AppURI:              mockURI,
		RedirectURI:         mockURI,
		Scope:               oauth.Permissions{"metaverse:read", "metaverse:write", "openid", "profile", "offline_access", "password", "email:verify"},
		Audience:            "snowcrash",
		CodeChallenge:       &challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(time.Minute * 10).Unix(),
		State:               &state,
		Subject:             &sub,
	}

	testCode = &oauth.AuthCode{
		AuthRequest:       *testRequest,
		Code:              "00000000-0000-0000-0000-000000000000",
		IssuedAt:          time.Now().Unix(),
		SessionID:         "00000000-0000-0000-0000-000000000000",
		Subject:           "00000000-0000-0000-0000-000000000000",
		UserAuthenticated: true,
	}

	testToken = mockRequestToken(testRequest)

	expiredReq = *testRequest
	expiredReq.ExpiresAt = time.Now().Add(time.Minute * -10).Unix()

	expiredToken = mockRequestToken(&expiredReq)

	badChallenge := *testRequest.CodeChallenge + "bad stuff"
	badReq := *testRequest
	badReq.CodeChallenge = &badChallenge

	badToken = mockRequestToken(&badReq)

	token = make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		panic(err)
	}

	misSum := sha256.Sum256(token)

	misChal := base64.RawURLEncoding.EncodeToString(misSum[:])

	misMatchReq := *testRequest
	misMatchReq.CodeChallenge = &misChal

	misMatchToken = mockRequestToken(&misMatchReq)

	emptyScopeReq = *testRequest
	emptyScopeReq.Scope = oauth.Permissions{}

	emptyScopeToken = mockRequestToken(&emptyScopeReq)
}

func scopeRequest(req *oauth.AuthRequest, scope ...string) *oauth.AuthRequest {
	rval := *req

	rval.Scope = append(rval.Scope, scope...)

	return &rval
}

func mockRequestToken(req *oauth.AuthRequest, src ...oauth.AuthRequest) string {
	signer := func(ctx context.Context, claims oauth.Claims) (string, error) {
		token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
		return token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	}

	if len(src) > 0 {
		mergo.Merge(&src[0], req, mergo.WithOverride)
		*req = src[0]
	}

	token, err := signValue(context.TODO(), signer, req)
	if err != nil {
		panic(err)
	}

	return token
}

func mockAccessToken(req *oauth.AuthRequest, expiresAt time.Time) (string, oauth.Claims) {
	signer := func(ctx context.Context, claims oauth.Claims) (string, error) {
		token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
		return token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	}

	claims := oauth.Claims{
		"iss":   mockURI,
		"use":   "access",
		"iat":   time.Now().Unix(),
		"aud":   req.Audience,
		"sub":   req.Subject,
		"scope": strings.Join(req.Scope, " "),
		"exp":   expiresAt.Unix(),
		"azp":   req.ClientID,
	}

	token, err := signValue(context.TODO(), signer, jwt.MapClaims(claims))
	if err != nil {
		panic(err)
	}

	return token, claims
}

func (c *MockController) ApplicationGet(ctx context.Context, id string) (*oauth.Application, error) {
	args := c.Called(ctx, id)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*oauth.Application), args.Error(1)
}

func (c *MockController) AudienceGet(ctx context.Context, name string) (oauth.Audience, error) {
	args := c.Called(ctx, name)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(oauth.Audience), args.Error(1)
}

func (c *MockController) UserGet(ctx context.Context, login string) (*oauth.User, interface{}, error) {
	args := c.Called(ctx, login)

	if args.Get(0) == nil {
		return nil, args.Get(1), args.Error(2)
	}

	return args.Get(0).(*oauth.User), args.Get(1), args.Error(2)
}

func (c *MockController) UserAuthenticate(ctx context.Context, login string, password string) (*oauth.User, interface{}, error) {
	args := c.Called(ctx, login, password)

	if args.Get(0) == nil {
		return nil, args.Get(1), args.Error(2)
	}

	return args.Get(0).(*oauth.User), args.Get(1), args.Error(2)
}

func (c *MockController) UserCreate(ctx context.Context, login string, password *string, profile *oauth.Profile, invite ...string) (*oauth.User, error) {
	args := c.Called(ctx, login, password, profile, invite)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	user := args.Get(0).(*oauth.User)

	user.Profile = profile
	user.Profile.Subject = "00000000-0000-0000-0000-000000000000"

	return user, args.Error(1)
}

func (c *MockController) UserVerify(ctx context.Context, id string, code string) error {
	return nil
}

func (c *MockController) UserUpdate(ctx context.Context, id string, profile *oauth.Profile) error {
	args := c.Called(ctx, id, profile)

	return args.Error(0)
}

func (c *MockController) UserResetPassword(ctx context.Context, login string, resetCode string) error {
	return nil
}

func (c *MockController) UserSetPassword(ctx context.Context, id string, password string) error {
	args := c.Called(ctx, id, password)

	return args.Error(0)
}

// UserNotify should create an email or sms with the verification link or code for the user
func (c *MockController) UserNotify(ctx context.Context, note oauth.Notification) error {
	args := c.Called(ctx, note)

	return args.Error(0)
}

func (c *MockController) TokenFinalize(ctx context.Context, claims oauth.Claims) (string, error) {
	args := c.Called(ctx, claims)

	if args.Get(0) == nil && args.Error(1) != nil {
		return "", args.Error(1)
	}

	if args.String(0) == "" {
		token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
		return token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	}

	return args.String(0), args.Error(1)
}

func (c *MockController) TokenValidate(ctx context.Context, bearerToken string) (oauth.Claims, error) {
	args := c.Called(ctx, bearerToken)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(oauth.Claims), args.Error(1)
}

// TokenGet gets a token by id
func (c *MockController) TokenGet(ctx context.Context, id string) (oauth.Claims, error) {
	return nil, nil
}

// TokenRevoke revokes a token by id
func (c *MockController) TokenRevoke(ctx context.Context, sub string, id string) error {
	return nil
}

// AuthCodeCreate creates a new authcode from the request if code expires at is set
// the store should use that value, otherwise set the defaults
func (c *MockController) AuthCodeCreate(ctx context.Context, code *oauth.AuthCode) error {
	args := c.Called(ctx, code)

	if code != nil {
		code.Code = "00000000-0000-0000-0000-000000000000"
	}

	return args.Error(0)
}

// AuthCodeGet returns a code from the store
func (c *MockController) AuthCodeGet(ctx context.Context, id string) (*oauth.AuthCode, error) {
	args := c.Called(ctx, id)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*oauth.AuthCode), args.Error(1)
}

// AuthCodeDestroy removes a code from the store
func (c *MockController) AuthCodeDestroy(ctx context.Context, id string) error {
	args := c.Called(ctx, id)

	return args.Error(0)
}

// SessionCreate creates a session
func (c *MockController) SessionCreate(ctx context.Context, r *http.Request) (oauth.Session, error) {
	args := c.Called(ctx, r)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(oauth.Session), args.Error(1)
}

// SessionRead retrieves the session from the request
func (c *MockController) SessionRead(ctx context.Context, r *http.Request) (oauth.Session, error) {
	args := c.Called(ctx, r)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(oauth.Session), args.Error(1)
}

// SessionDestroy destroys the session in the response
func (c *MockController) SessionDestroy(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	args := c.Called(ctx, w, r)

	return args.Error(0)
}

func (c *MockController) Authorize(opts ...oauth.AuthOption) api.Authorizer {
	return func(r *http.Request) (context.Context, error) {
		return context.TODO(), nil
	}
}

func (c *MockAuthorizer) Authorize(opts ...oauth.AuthOption) api.Authorizer {
	return func(r *http.Request) (context.Context, error) {
		if c.handler == nil {
			return context.TODO(), nil
		}
		return c.handler(r)
	}
}

func (c *MockAuthorizer) Handler(h api.Authorizer) {
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

// Subject is the user subject id
func (s *mockSession) Scope(aud string) oauth.Permissions {
	return oauth.Permissions{}
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

func (a mockAudience) Name() string {
	return a.name
}

func (a mockAudience) Description() string {
	if a.description == nil {
		return ""
	}
	return *a.description
}

func (a mockAudience) Permissions() oauth.Permissions {
	return a.permissions
}

func (a mockAudience) TokenAlgorithm() string {
	return a.tokenAlgorithm
}

func (a mockAudience) TokenLifetime() int64 {
	return a.tokenLifetime
}

func (a mockAudience) TokenSecret() string {
	return a.tokenSecret
}

func (a mockAudience) VerifyKey() interface{} {
	return &a.key.PublicKey
}

func (a mockAudience) Principal() interface{} {
	return &a
}
