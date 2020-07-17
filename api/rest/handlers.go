/*
 * Copyright (C) 2020 Atomic Media Foundation
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file in the root of this
 * workspace for details.
 */

package rest

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/libatomic/oauth/api/rest/auth"
	"github.com/libatomic/oauth/pkg/oauth"

	"github.com/mitchellh/mapstructure"
	"github.com/mr-tron/base58"
)

const (
	// AuthRequestParam is the name of the request token parameter
	AuthRequestParam = "request_token"

	// SessionCookie is the name the session cookie
	SessionCookie = "_atomic_session"
)

type (
	sessionToken struct {
		Timeout   int64
		SessionID string
	}
)

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	params := auth.NewLoginParams()

	if err := params.BindRequest(r); err != nil {
		s.writeErr(w, http.StatusInternalServerError, err)
		return
	}

	req := &oauth.AuthRequest{}
	if err := s.cookie.Decode(AuthRequestParam, params.RequestToken, req); err != nil {
		s.writeErr(w, http.StatusBadRequest, err)
		return
	}

	if time.Unix(req.ExpiresAt, 0).Before(time.Now()) {
		s.writeError(w, http.StatusUnauthorized, "expired request token")
		return
	}

	u, _ := url.Parse(req.RedirectURI)

	// validate the code verifier
	verifier, err := base64.RawURLEncoding.DecodeString(params.CodeVerifier)
	if err != nil {
		s.log.Errorln(err)

		s.redirectError(w, u, map[string]string{
			"error":             "invalid_request",
			"error_description": "invalid code_verifier",
		})

		return
	}
	code := sha256.Sum256([]byte(verifier))

	// validate the code challenge
	chal, err := base64.RawURLEncoding.DecodeString(req.CodeChallenge)
	if err != nil {
		s.log.Errorln(err)

		s.redirectError(w, u, map[string]string{
			"error":             "invalid_request",
			"error_description": "invalid code_challenge",
		})

		return
	}

	// verify the code verifier against the challenge
	if !bytes.Equal(code[:], chal) {
		s.log.Errorln(err)

		s.redirectError(w, u, map[string]string{
			"error":             "invalid_request",
			"error_description": "code verification failed",
		})

		return
	}

	user, err := s.ctrl.UserAuthenticate(params.Login, params.Password)
	if err != nil {
		s.log.Errorln(err)

		s.redirectError(w, u, map[string]string{
			"error":             "access_denied",
			"error_description": "user authentication failed",
		})

		return
	}

	perms, ok := user.Permissions[req.Audience]
	if !ok {
		s.redirectError(w, u, map[string]string{
			"error":             "access_denied",
			"error_description": "user authorization failed",
		})

		return
	}

	if len(req.Scope) == 0 {
		req.Scope = perms
	}

	if !every(perms, req.Scope...) {
		s.redirectError(w, u, map[string]string{
			"error":             "access_denied",
			"error_description": "user authorization failed",
		})

		return
	}

	session, err := s.sessions.Get(r, s.sessionCookie)
	if err != nil {
		s.log.Errorln(err)

		s.redirectError(w, u, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})

		return
	}

	sessionID := session.ID

	if sessionID == "" {
		// since the store did not create an id so generate one
		// we only need one to determine if a session exists
		id := uuid.Must(uuid.NewRandom())
		sessionID = base58.Encode(id[:])
	}

	session.Values["state"] = &oauth.Session{
		ID:        sessionID,
		ClientID:  req.ClientID,
		Subject:   user.Profile.Subject,
		CreatedAt: time.Now().Unix(),
		ExpiresAt: time.Now().Add(s.sessionLifetime).Unix(),
	}

	session.Values["timeout"] = &sessionToken{
		SessionID: sessionID,
		Timeout:   time.Now().Add(s.sessionTimeout).Unix(),
	}

	session.Options.Path = "/"

	if err := session.Save(r, w); err != nil {
		s.log.Errorln(err)

		s.redirectError(w, u, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})

		return
	}

	authCode := &oauth.AuthCode{
		AuthRequest:       *req,
		Subject:           user.Profile.Subject,
		SessionID:         session.ID,
		UserAuthenticated: true,
	}
	if err := s.codes.CodeCreate(authCode); err != nil {

		s.log.Errorln(err)

		s.redirectError(w, u, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})

		return
	}

	u, _ = url.Parse(req.RedirectURI)

	q := u.Query()

	q.Set("code", authCode.Code)

	if req.State != nil {
		q.Set("state", *req.State)
	}

	u.RawQuery = q.Encode()

	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) signup(w http.ResponseWriter, r *http.Request) {
	params := auth.NewSignupParams()

	if err := params.BindRequest(r); err != nil {
		s.writeErr(w, http.StatusInternalServerError, err)
		return
	}

	if !s.allowSignup && params.InviteCode == nil {
		s.writeError(w, http.StatusUnauthorized, "user self-registration disabled")
		return
	}

	req := &oauth.AuthRequest{}
	if err := s.cookie.Decode(AuthRequestParam, params.RequestToken, req); err != nil {
		s.writeErr(w, http.StatusBadRequest, err)
		return
	}

	if time.Unix(req.ExpiresAt, 0).Before(time.Now()) {
		s.writeError(w, http.StatusUnauthorized, "expired request token")
		return
	}

	user := &oauth.User{
		Login: params.Login,
		Profile: &oauth.Profile{
			Name:  safestr(params.Name),
			Email: params.Email,
		},
	}

	if err := s.ctrl.UserCreate(user, params.Password, safestr(params.InviteCode)); err != nil {
		s.writeErr(w, http.StatusBadRequest, err)
		return
	}

	// pass the request login
	s.login(w, r)
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	params := auth.NewAuthorizeParams()

	if err := params.BindRequest(r); err != nil {
		s.writeErr(w, http.StatusInternalServerError, err)
		return
	}

	// ensure this is a valid application
	app, err := s.ctrl.ApplicationGet(params.ClientID)
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, err)
		return
	}

	// enusure this app supports the authorization_code flow
	if !contains(app.AllowedGrants, "authorization_code") {
		s.writeError(w, http.StatusUnauthorized, "authorization_code grant not permitted")
		return
	}

	if params.RedirectURI == nil {
		params.RedirectURI = &app.RedirectUris[0]
	}

	// all errors should go to the redirect uri
	u, err := url.Parse(*params.RedirectURI)
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, err)
		return
	}

	// ensure the redirect uri path is allowed
	if !contains(app.RedirectUris, path.Join("/", u.Path)) {
		s.writeError(w, http.StatusUnauthorized, "unauthorized redirect uri")
		return
	}

	if params.AppURI == nil {
		params.AppURI = &app.AppUris[0]
	}

	{
		// ensure the login uri is allowed
		u, err := url.Parse(*params.AppURI)
		if err != nil {
			s.log.Errorln(err)

			s.redirectError(w, u, map[string]string{
				"error":             "access_denied",
				"error_description": "invalid app uri",
			})

			return
		}

		if !contains(app.AppUris, path.Join("/", u.Path)) {
			s.redirectError(w, u, map[string]string{
				"error":             "access_denied",
				"error_description": "unauthorized app uri",
			})

			return
		}
	}

	// ensure the audience
	aud, err := s.ctrl.AudienceGet(params.Audience)
	if err != nil {
		s.log.Errorln(err)

		s.redirectError(w, u, map[string]string{
			"error":             "bad_request",
			"error_description": "invalid audience",
		})

		return
	}

	if len(params.Scope) > 0 {
		// check the scope against the app and audience
		perms, ok := app.Permissions[params.Audience]
		if !ok || !every(perms, params.Scope...) {
			s.redirectError(w, u, map[string]string{
				"error":             "access_denied",
				"error_description": "insufficient permissions",
			})

			return
		}

		// sanity check to ensure the audience actually has the permissions requested
		if !every(aud.Permissions, params.Scope...) {
			s.redirectError(w, u, map[string]string{
				"error":             "access_denied",
				"error_description": "insufficient permissions",
			})

			return
		}
	}

	req := &oauth.AuthRequest{
		ClientID:            params.ClientID,
		RedirectURI:         *params.RedirectURI,
		Scope:               params.Scope,
		Audience:            params.Audience,
		State:               params.State,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: *params.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(time.Minute * 10).Unix(),
	}

	session, state, err := s.getSession(r)
	if err != nil {
		s.log.Errorln(err)

		s.redirectError(w, u, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})

		return
	}

	// if we already gave a session, use that to create the code
	if state.ID != "" {
		session.Values["state"] = state

		session.Values["timeout"] = &sessionToken{
			SessionID: state.ID,
			Timeout:   time.Now().Add(s.sessionTimeout).Unix(),
		}

		if err := session.Save(r, w); err != nil {
			s.log.Errorln(err)

			s.redirectError(w, u, map[string]string{
				"error":             "server_error",
				"error_description": err.Error(),
			})

			return
		}

		authCode := &oauth.AuthCode{
			AuthRequest: *req,
			Subject:     state.Subject,
			SessionID:   session.ID,
		}
		if err := s.codes.CodeCreate(authCode); err != nil {
			s.log.Errorln(err)

			s.redirectError(w, u, map[string]string{
				"error":             "server_error",
				"error_description": err.Error(),
			})

			return
		}

		q := u.Query()

		q.Set("code", authCode.Code)

		if req.State != nil {
			q.Set("state", *req.State)
		}

		u.RawQuery = q.Encode()

		http.Redirect(w, r, u.String(), http.StatusFound)

		return
	}

	if err := s.destroySession(w, r); err != nil {
		s.log.Errorln(err)

		s.redirectError(w, u, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})

		return
	}

	u, err = url.Parse(*params.AppURI)
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, err)
		return
	}

	token, err := s.cookie.Encode(AuthRequestParam, req)
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, err)
		return
	}

	q := u.Query()
	q.Set(AuthRequestParam, token)
	u.RawQuery = q.Encode()

	w.Header().Add("Location", u.String())

	w.WriteHeader(http.StatusFound)
}

func (s *Server) publicKey(w http.ResponseWriter, r *http.Request) {
	// create the jwks output
	key, err := jwk.New(&s.signingKey.PublicKey)
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, err)
		return
	}

	thumb, err := key.Thumbprint(crypto.SHA1)
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, err)
		return
	}

	// usw the thumbprint as kid and x5t
	key.Set("kid", hex.EncodeToString(thumb))
	key.Set("x5t", base64.RawURLEncoding.EncodeToString(thumb))

	key.Set("alg", "RS256")
	key.Set("use", "sig")

	keys := map[string]interface{}{
		"keys": []interface{}{key},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "\t")

	if err := enc.Encode(keys); err != nil {
		s.writeErr(w, http.StatusInternalServerError, err)
		return
	}
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	params := auth.NewTokenParams()

	if err := params.BindRequest(r); err != nil {
		s.writeErr(w, http.StatusInternalServerError, err)
		return
	}

	// ensure this is a valid application
	app, err := s.ctrl.ApplicationGet(params.ClientID)
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, err)
		return
	}

	bearer := &oauth.BearerToken{
		TokenType: "bearer",
	}

	if !contains(app.AllowedGrants, params.GrantType) {
		s.writeError(w, http.StatusUnauthorized, "unauthorized grant")
		return
	}

	var aud *oauth.Audience

	signToken := func(claims jwt.MapClaims) (string, error) {
		var token *jwt.Token
		var key interface{}

		claims["iss"] = fmt.Sprintf("https://%s%s", r.Host, path.Clean(path.Join(path.Dir(r.URL.Path), "/.well-known/jwks.json")))

		switch aud.TokenAlgorithm {
		case "RS256":
			token = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			key = s.signingKey

		case "HS256":
			token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
			key = []byte(aud.TokenSecret)
		}
		return token.SignedString(key)
	}

	var code *oauth.AuthCode

	switch params.GrantType {
	case oauth.GrantTypeClientCredentials:
		if params.ClientSecret == nil || *params.ClientSecret != app.ClientSecret {
			s.writeError(w, http.StatusUnauthorized, "bad client secret")
			return
		}

		if params.Audience == nil {
			s.writeError(w, http.StatusUnauthorized, "missing audience")
			return
		}

		// ensure the audience
		aud, err = s.ctrl.AudienceGet(*params.Audience)
		if err != nil {
			s.log.Errorln(err)

			s.writeErr(w, http.StatusBadRequest, err)
			return
		}

		// sanity check to ensure the audience actually has the permissions requested
		if !every(aud.Permissions, params.Scope...) {
			s.writeError(w, http.StatusUnauthorized, "bad scope")
			return
		}

		// ensure this app has these permissions
		perms, ok := app.Permissions[*params.Audience]
		if !ok || !every(perms, params.Scope...) {
			s.writeError(w, http.StatusUnauthorized, "bad scope")
			return
		}

		claims := make(jwt.MapClaims)

		exp := time.Now().Add(time.Second * time.Duration(aud.TokenLifetime)).Unix()

		claims["sub"] = fmt.Sprintf("%s@applications", app.ClientID)
		claims["aud"] = aud.Name
		claims["exp"] = exp
		claims["iat"] = time.Now().Unix()
		claims["scope"] = strings.Join(params.Scope, " ")

		token, err := signToken(claims)
		if err != nil {
			s.writeErr(w, http.StatusInternalServerError, err)
			return
		}
		bearer.AccessToken = token
		bearer.ExpiresIn = int64(exp - time.Now().Unix())

	case oauth.GrantTypeRefreshToken:
		if params.RefreshToken == nil || params.RefreshVerifier == nil {
			s.writeError(w, http.StatusBadRequest, "missing refresh token or verifier")
			return
		}

		code, err = s.codes.CodeGet(*params.RefreshToken)
		if err != nil {
			s.writeError(w, http.StatusUnauthorized, "invalid refresh token")
			return
		}

		verifier, err := base64.RawURLEncoding.DecodeString(*params.RefreshVerifier)
		if err != nil {
			s.log.Errorln(err)

			s.writeErr(w, http.StatusInternalServerError, err)
			return
		}
		sum := sha256.Sum256(verifier)
		check := base64.RawURLEncoding.EncodeToString(sum[:])

		if code.RefreshNonce != check {
			s.writeError(w, http.StatusUnauthorized, "token validation failed")
			return
		}

		fallthrough

	case oauth.GrantTypeAuthCode:
		if code == nil {
			if params.Code == nil || params.CodeVerifier == nil {
				s.writeError(w, http.StatusBadRequest, "missing code or verifier")
				return
			}

			code, err = s.codes.CodeGet(*params.Code)
			if err != nil {
				s.writeError(w, http.StatusUnauthorized, "invalid code")
				return
			}

			verifier, err := base64.RawURLEncoding.DecodeString(*params.CodeVerifier)
			if err != nil {
				s.log.Errorln(err)

				s.writeErr(w, http.StatusInternalServerError, err)
				return
			}
			sum := sha256.Sum256(verifier)
			check := base64.RawURLEncoding.EncodeToString(sum[:])

			if code.CodeChallenge != check {
				s.log.Errorln(err)

				s.writeErr(w, http.StatusInternalServerError, err)
				return
			}
		}

		s.codes.CodeDestroy(code.Code)

		aud, err = s.ctrl.AudienceGet(code.Audience)
		if err != nil {
			s.log.Errorln(err)

			s.writeErr(w, http.StatusBadRequest, err)
			return
		}

		_, state, err := s.getSession(r)
		if err != nil {
			s.log.Errorln(err)

			s.writeErr(w, http.StatusInternalServerError, err)
			return
		}

		if state.ID == "" {
			s.writeError(w, http.StatusUnauthorized, "session does not exist")
			return
		}

		user, err := s.ctrl.UserGet(state.Subject)
		if err != nil {
			s.log.Errorln(err)

			s.writeError(w, http.StatusUnauthorized, err.Error())
			return
		}

		perms, ok := user.Permissions[code.Audience]
		if len(params.Scope) == 0 {
			params.Scope = code.Scope
		}

		// check the scope against the code
		if !ok || !every(code.Scope, params.Scope...) {
			s.writeError(w, http.StatusUnauthorized, "invalid scope")

			return
		}

		// sanity check to ensure the api provides these permissions
		if !every(aud.Permissions, params.Scope...) {
			s.writeError(w, http.StatusUnauthorized, "invalid scope")

			return
		}

		// ensure the app has access to this audience
		perms, ok = app.Permissions[aud.Name]
		// check the scope against the app, audience and user permissions
		if !ok || !every(perms, params.Scope...) {
			s.writeError(w, http.StatusUnauthorized, "invalid scope")

			return
		}

		// ensure the user has access to this audience
		perms, ok = user.Permissions[aud.Name]
		if !ok || !every(perms, params.Scope...) {
			s.writeError(w, http.StatusUnauthorized, "invalid scope")

			return
		}

		exp := time.Now().Add(time.Second * time.Duration(aud.TokenLifetime)).Unix()

		claims := jwt.MapClaims{
			"iat":   time.Now().Unix(),
			"aud":   aud.Name,
			"sub":   state.Subject,
			"scope": strings.Join(params.Scope, " "),
			"exp":   exp,
			"azp":   state.ID,
		}

		token, err := signToken(claims)
		if err != nil {
			s.log.Errorln(err)

			s.writeErr(w, http.StatusInternalServerError, err)
			return
		}
		bearer.AccessToken = token
		bearer.ExpiresIn = int64(exp - time.Now().Unix())

		// check for offline_access
		if contains(params.Scope, oauth.ScopeOffline) {
			if params.RefreshNonce == nil || code.RefreshNonce == *params.RefreshNonce {
				s.writeError(w, http.StatusUnauthorized, "invalid refresh nonce")
				return
			}

			code.ExpiresAt = time.Now().Add(time.Hour * 168).Unix()
			code.RefreshNonce = *params.RefreshNonce

			if err := s.codes.CodeCreate(code); err != nil {
				s.log.Errorln(err)

				s.writeErr(w, http.StatusInternalServerError, err)
				return
			}

			bearer.RefreshToken = code.Code
		}

		// check for id token request
		if contains(params.Scope, oauth.ScopeOpenID) {
			claims := jwt.MapClaims{
				"iat":       time.Now().Unix(),
				"auth_time": state.CreatedAt,
				"aud":       aud.Name,
				"sub":       state.Subject,
				"exp":       time.Now().Add(time.Duration(app.TokenLifetime)).Unix(),
				"azp":       state.ID,
				"name":      user.Profile.Name,
			}

			if contains(params.Scope, oauth.ScopeProfile) {
				dec, _ := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
					TagName: "json",
					Result:  &claims,
				})

				if err := dec.Decode(user.Profile); err != nil {
					s.log.Errorln(err)

					s.writeErr(w, http.StatusInternalServerError, err)
					return
				}
			}

			token, err := signToken(claims)
			if err != nil {
				s.log.Errorln(err)

				s.writeErr(w, http.StatusInternalServerError, err)
				return
			}
			bearer.IDToken = token
		}

	default:
		s.writeError(w, http.StatusUnauthorized, "invalid grant type")
		return
	}

	s.writeJSON(w, http.StatusOK, bearer, true)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	params := auth.NewLogoutParams()

	if err := params.BindRequest(r); err != nil {
		s.writeErr(w, http.StatusInternalServerError, err)
		return
	}

	// ensure this is a valid application
	app, err := s.ctrl.ApplicationGet(params.ClientID)
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, err)
		return
	}

	if params.RedirectURI == nil {
		params.RedirectURI = &app.RedirectUris[0]
	}

	u, err := url.Parse(*params.RedirectURI)
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, err)
		return
	}

	if params.RedirectURI == nil {
		params.RedirectURI = &app.AppUris[0]
	}

	// ensure the redirect uri is allowed
	if !contains(app.AppUris, path.Join("/", u.Path)) {
		s.writeError(w, http.StatusUnauthorized, "unauthorized logout uri")
		return
	}

	if err := s.destroySession(w, r); err != nil {
		s.log.Errorln(err)

		s.redirectError(w, u, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})

		return
	}

	q := u.Query()

	if params.State != nil {
		q.Set("state", *params.State)
	}

	u.RawQuery = q.Encode()

	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) userInfo(w http.ResponseWriter, r *http.Request) {
	_, prin, err := s.AuthorizeRequest(r, []string{"openid", "profile"})
	if err != nil {
		s.writeErr(w, http.StatusUnauthorized, err)
		return
	}

	user, ok := prin.(*oauth.User)
	if !ok || user == nil {
		s.writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}

	_, state, err := s.getSession(r)
	if err != nil {
		s.log.Errorln(err)

		s.writeErr(w, http.StatusInternalServerError, err)
		return
	}

	if state.ID == "" {
		s.writeError(w, http.StatusUnauthorized, "session does not exist")
		return
	}

	if user.Profile == nil || user.Profile.Subject != state.Subject {
		s.writeError(w, http.StatusUnauthorized, "access denied")
		return
	}

	s.writeJSON(w, http.StatusOK, user.Profile, true)
}

func (s *Server) getSession(r *http.Request) (*sessions.Session, *oauth.Session, error) {
	c, err := s.sessions.Get(r, s.sessionCookie)
	if err != nil {
		return nil, nil, err
	}

	// check the session activity timeout
	val, ok := c.Values["timeout"]
	if !ok {
		return c, &oauth.Session{}, nil
	}

	// ensure the token
	to, ok := val.(sessionToken)
	if ok {
		if time.Unix(to.Timeout, 0).Before(time.Now()) {
			return c, &oauth.Session{}, nil
		}
	} else {
		return c, &oauth.Session{}, nil
	}

	// check for the state
	val, ok = c.Values["state"]
	if !ok {
		return c, &oauth.Session{}, nil
	}

	// ensure the session object
	state, ok := val.(oauth.Session)
	if !ok {
		return c, &oauth.Session{}, nil
	}

	// sanity check the token and the state
	if state.ID != to.SessionID {
		return c, &oauth.Session{}, nil
	}

	// sanity check the session expiration
	if time.Unix(state.ExpiresAt, 0).Before(time.Now()) {
		return c, &oauth.Session{}, nil
	}

	return c, &state, nil
}

func (s *Server) destroySession(w http.ResponseWriter, r *http.Request) error {
	c, err := s.sessions.Get(r, s.sessionCookie)
	if err != nil {
		return err
	}

	c.Values["state"] = &oauth.Session{}
	c.Values["timeout"] = &sessionToken{}
	c.Options.MaxAge = -1

	return c.Save(r, w)
}
