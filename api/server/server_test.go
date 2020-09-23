package server

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/google/uuid"
	"github.com/libatomic/oauth/pkg/oauth"
)

type (
	mockController struct{}
)

var (
	srv  *Server
	ctrl = &mockController{}

	verifier  string
	challenge string
)

const (
	mockURI = "https://meta.org/"
)

func setup() error {
	srv = New(ctrl, oauth.NewAuthorizer(ctrl), AllowPasswordGrant(true))

	token := make([]byte, 32)

	if _, err := rand.Read(token); err != nil {
		return err
	}

	verifier = base64.RawURLEncoding.EncodeToString(token)

	sum := sha256.Sum256(token)

	challenge = base64.RawURLEncoding.EncodeToString(sum[:])

	return nil
}

func TestMain(m *testing.M) {
	log.Println("starting tests")
	if err := setup(); err != nil {
		log.Fatalln(err)
	}

	exitVal := m.Run()

	os.Exit(exitVal)
}

func TestAuthorize(t *testing.T) {
	loc, _ := getAuthRequest(mockURI, t)

	if !strings.HasPrefix(loc, mockURI) {
		t.Errorf("handler returned unexpected location header: got %v want %v",
			loc, mockURI)
	}
}

func TestAuthorizeWithURIParams(t *testing.T) {
	p := fmt.Sprintf("%s?foo=bar", mockURI)

	loc, _ := getAuthRequest(p, t)

	if !strings.HasPrefix(loc, mockURI) {
		t.Errorf("handler returned unexpected location header: got %v want %v",
			loc, mockURI)
	}
}

func TestLogin(t *testing.T) {
	loc, code := getAuthCode(mockURI, t)

	if !strings.HasPrefix(loc, mockURI) {
		t.Errorf("handler returned unexpected location header: got %v want %v",
			loc, mockURI)
	}

	t.Logf("got authcode %s", code)
}

func TestAuthCodeToken(t *testing.T) {
	token := getAuthCodeToken(mockURI, t)

	t.Logf("got bearer token %s", token.AccessToken)
}

func TestRefreshToken(t *testing.T) {
	token := getRefreshToken(t)

	t.Logf("got bearer token %s", token.AccessToken)
}

func TestUserInfoGet(t *testing.T) {
	token := getAuthCodeToken(mockURI, t)

	req, err := http.NewRequest("GET", "/oauth/userInfo", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))

	rr := httptest.NewRecorder()

	srv.Router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	data, err := ioutil.ReadAll(rr.Body)
	if err != nil {
		t.Errorf("invalid token body")
	}

	profile := oauth.Profile{}
	if err := json.Unmarshal(data, &profile); err != nil {
		t.Errorf("invalid profile body %w", err)
	}

	if profile.FamilyName != "Protagonist" || profile.GivenName != "Hiro" {
		t.Errorf("handler returned unexpected profile data: %#v", profile)
	}
}

func TestClientCredentialsToken(t *testing.T) {
	form := url.Values{}
	form.Add("client_id", uuid.Must(uuid.NewRandom()).String())
	form.Add("client_secret", "super-secret")
	form.Add("grant_type", oauth.GrantTypeClientCredentials)
	form.Add("audience", "snowcrash")
	form.Add("scope", "metaverse:read metaverse:write openid profile offline_access")

	req, err := http.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()

	srv.Router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	data, err := ioutil.ReadAll(rr.Body)
	if err != nil {
		t.Errorf("invalid token body")
	}

	token := &oauth.BearerToken{}
	if err := json.Unmarshal(data, token); err != nil {
		t.Errorf("invalid token body %w", err)
	}
}

func TestUserPasswordToken(t *testing.T) {
	form := url.Values{}
	form.Add("client_id", uuid.Must(uuid.NewRandom()).String())
	form.Add("client_secret", "super-secret")
	form.Add("username", "hiro@metaverse.org")
	form.Add("password", "ratTh1Ng$")
	form.Add("grant_type", oauth.GrantTypePassword)
	form.Add("audience", "snowcrash")
	form.Add("scope", "metaverse:read metaverse:write openid profile offline_access")

	req, err := http.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()

	srv.Router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	data, err := ioutil.ReadAll(rr.Body)
	if err != nil {
		t.Errorf("invalid token body")
	}

	token := &oauth.BearerToken{}
	if err := json.Unmarshal(data, token); err != nil {
		t.Errorf("invalid token body %w", err)
	}
}

func TestUserInfoUpdate(t *testing.T) {
	token := getAuthCodeToken(mockURI, t)

	profile := oauth.Profile{
		FamilyName: "Stephenson",
		GivenName:  "Neal",
	}
	data, _ := json.Marshal(profile)

	req, err := http.NewRequest("PUT", "/oauth/userInfo", bytes.NewBuffer(data))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))

	rr := httptest.NewRecorder()

	srv.Router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	data, err = ioutil.ReadAll(rr.Body)
	if err != nil {
		t.Errorf("invalid token body")
	}

	profile = oauth.Profile{}
	if err := json.Unmarshal(data, &profile); err != nil {
		t.Errorf("invalid profile body %w", err)
	}

	if profile.FamilyName != "Stephenson" || profile.GivenName != "Neal" {
		t.Errorf("handler returned unexpected profile data: %#v", profile)
	}
}

func TestUserPrincipal(t *testing.T) {
	token := getAuthCodeToken(mockURI, t)

	req, err := http.NewRequest("GET", "/oauth/userPrincipal", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))

	rr := httptest.NewRecorder()

	srv.Router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	data, err := ioutil.ReadAll(rr.Body)
	if err != nil {
		t.Errorf("invalid token body")
	}

	prin := make(map[string]interface{})
	if err := json.Unmarshal(data, &prin); err != nil {
		t.Errorf("invalid profile body %w", err)
	}

	if bff, ok := prin["bff"].(string); !ok || bff != "yt" {
		t.Errorf("handler returned unexpected principal data: %#v", prin)
	}
}

// getAuthRequest returns the request token and is used in several methods
func getAuthRequest(uri string, t *testing.T) (string, string) {
	req, err := http.NewRequest("GET", "/oauth/authorize", nil)
	if err != nil {
		t.Fatal(err)
	}
	q := req.URL.Query()

	q.Add("response_type", "code")
	q.Add("client_id", uuid.Must(uuid.NewRandom()).String())
	q.Add("audience", "snowcrash")
	q.Add("app_uri", uri)
	q.Add("redirect_uri", uri)
	q.Add("scope", "metaverse:read metaverse:write openid profile offline_access")
	q.Add("code_challenge", challenge)

	req.URL.RawQuery = q.Encode()

	rr := httptest.NewRecorder()

	srv.Router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusFound {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	u, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Errorf("failed to parse location header %w", err)
	}

	return u.String(), u.Query().Get("request_token")
}

func getAuthCode(uri string, t *testing.T) (string, string) {
	_, token := getAuthRequest(uri, t)

	form := url.Values{}
	form.Add("client_id", uuid.Must(uuid.NewRandom()).String())
	form.Add("login", "hiro")
	form.Add("password", "ratTh1Ng$")
	form.Add("code_verifier", verifier)
	form.Add("request_token", token)

	req, err := http.NewRequest("POST", "/oauth/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()

	srv.Router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusFound {
		t.Fatalf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	u, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("failed to parse location header %s", err.Error())
	}

	return u.String(), u.Query().Get("code")
}

func getAuthCodeToken(uri string, t *testing.T) *oauth.BearerToken {
	_, code := getAuthCode(uri, t)

	form := url.Values{}
	form.Add("client_id", uuid.Must(uuid.NewRandom()).String())
	form.Add("grant_type", oauth.GrantTypeAuthCode)
	form.Add("audience", "snowcrash")
	form.Add("scope", "metaverse:read metaverse:write openid profile offline_access")
	form.Add("code", code)
	form.Add("code_verifier", verifier)
	form.Add("refresh_nonce", challenge)

	req, err := http.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()

	srv.Router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Fatalf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	data, err := ioutil.ReadAll(rr.Body)
	if err != nil {
		t.Fatalf("invalid token body")
	}

	token := &oauth.BearerToken{}
	if err := json.Unmarshal(data, token); err != nil {
		t.Fatalf("invalid token body:%s", err.Error())
	}

	return token
}

func getRefreshToken(t *testing.T) *oauth.BearerToken {
	token := getAuthCodeToken(mockURI, t)

	form := url.Values{}
	form.Add("client_id", uuid.Must(uuid.NewRandom()).String())
	form.Add("grant_type", oauth.GrantTypeRefreshToken)
	form.Add("audience", "snowcrash")
	form.Add("scope", "metaverse:read metaverse:write openid profile offline_access")
	form.Add("refresh_token", token.RefreshToken)
	form.Add("refresh_verifier", verifier)
	form.Add("refresh_nonce", verifier)

	req, err := http.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()

	srv.Router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	data, err := ioutil.ReadAll(rr.Body)
	if err != nil {
		t.Errorf("invalid token body")
	}

	token = &oauth.BearerToken{}
	if err := json.Unmarshal(data, token); err != nil {
		t.Errorf("invalid token body %w", err)
	}

	return token
}

func (c *mockController) ApplicationGet(ctx context.Context, id string) (*oauth.Application, error) {
	return &oauth.Application{
		ClientID:     id,
		ClientSecret: "super-secret",
		Permissions: oauth.PermissionSet{
			"snowcrash": oauth.Permissions{"metaverse:read", "metaverse:write", "openid", "profile", "offline_access"},
		},
		AllowedGrants: oauth.Permissions{
			oauth.GrantTypeClientCredentials,
			oauth.GrantTypeAuthCode,
			oauth.GrantTypePassword,
			oauth.GrantTypeRefreshToken,
		},
		AppUris:       oauth.Permissions{mockURI},
		RedirectUris:  oauth.Permissions{mockURI},
		TokenLifetime: 60,
	}, nil
}

func (c *mockController) AudienceGet(ctx context.Context, name string) (*oauth.Audience, error) {
	return &oauth.Audience{
		Name:           name,
		Permissions:    oauth.Permissions{"metaverse:read", "metaverse:write", "openid", "profile", "offline_access"},
		TokenAlgorithm: "HS256",
		TokenSecret:    "super-duper-secret",
		TokenLifetime:  60,
	}, nil
}

func (c *mockController) UserGet(ctx oauth.Context, id string) (*oauth.User, interface{}, error) {
	return &oauth.User{
		Login:             "hiro@metaverse.org",
		PasswordExpiresAt: strfmt.DateTime(time.Now().Add(time.Hour)),
		Permissions: oauth.PermissionSet{
			"snowcrash": oauth.Permissions{"metaverse:read", "metaverse:write", "openid", "profile", "offline_access"},
		},
		Profile: oauth.Profile{
			Subject:    id,
			GivenName:  "Hiro",
			FamilyName: "Protagonist",
		},
	}, map[string]interface{}{"bff": "yt"}, nil
}

func (c *mockController) UserAuthenticate(ctx oauth.Context, login string, password string) (*oauth.User, interface{}, error) {
	return &oauth.User{
		Login:             "hiro@metaverse.org",
		PasswordExpiresAt: strfmt.DateTime(time.Now().Add(time.Hour)),
		Permissions: oauth.PermissionSet{
			"snowcrash": oauth.Permissions{"metaverse:read", "metaverse:write", "openid", "profile", "offline_access"},
		},
		Profile: oauth.Profile{
			Subject:    uuid.Must(uuid.NewRandom()).String(),
			GivenName:  "Hiro",
			FamilyName: "Protagonist",
		},
	}, map[string]interface{}{"bff": "yt"}, nil
}

func (c *mockController) UserCreate(ctx oauth.Context, user oauth.User, password string, invite ...string) (*oauth.User, error) {
	return &user, nil
}

func (c *mockController) UserVerify(ctx oauth.Context, id string, code string) error {
	return nil
}

func (c *mockController) UserUpdate(ctx oauth.Context, user *oauth.User) error {
	return nil
}

func (c *mockController) UserResetPassword(ctx oauth.Context, login string, resetCode string) error {
	return nil
}

func (c *mockController) UserSetPassword(ctx oauth.Context, id string, password string) error {
	return nil
}

func (c *mockController) TokenFinalize(ctx oauth.Context, scope oauth.Permissions, claims map[string]interface{}) {

}

func (c *mockController) TokenPrivateKey(ctx oauth.Context) (*rsa.PrivateKey, error) {
	// tests use HS256 so we dont need a signing key
	return nil, nil
}

func (c *mockController) TokenPublicKey(ctx oauth.Context) (*rsa.PublicKey, error) {
	// tests use HS256 so we dont need a signing key
	return nil, nil
}
