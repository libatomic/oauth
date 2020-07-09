/*
 * Copyright (C) 2020 Atomic Media Foundation
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file in the root of this
 * workspace for details.
 */

package server

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
	"github.com/libatomic/oauth/api/types"
	"github.com/libatomic/oauth/api/types/auth"
	"github.com/libatomic/oauth/pkg/oauth"
	"github.com/mitchellh/mapstructure"
	"github.com/mr-tron/base58"
	"github.com/thoas/go-funk"
)

const (
	// AuthRequestParam is the name of the request token parameter
	AuthRequestParam = "request_token"

	// SessionCookie is the name the session cookie
	SessionCookie = "_tl_session"

	// SessionTokenCookie is the parameter used to track the session activity
	SessionTokenCookie = "_tl_session_token"
)

type (
	sessionToken struct {
		Timeout   int64
		SessionID string
	}
)

func wrap(val []string, without ...string) []interface{} {
	out := make([]interface{}, 0)
	for _, s := range val {
		if !funk.Contains(without, s) {
			out = append(out, s)
		}
	}
	return out
}

func checkScope(scope []string, check ...[]string) bool {
	for _, c := range check {
		// check the scope against the app
		if !funk.Every(c, wrap(scope)...) {
			return false
		}
	}
	return true
}

func without(s []string, w ...string) []string {
	r := make([]string, 0)
	for _, v := range s {
		if !funk.Contains(w, v) {
			r = append(r, v)
		}
	}
	return r
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	params := auth.NewLoginParams()

	if err := params.BindRequest(r); err != nil {
		s.writeErr(w, http.StatusInternalServerError, err)
		return
	}

	req := &types.AuthRequest{}
	if err := s.cookie.Decode(AuthRequestParam, params.RequestToken, req); err != nil {
		s.writeErr(w, http.StatusBadRequest, err)
		return
	}

	if time.Unix(req.ExpiresAt, 0).Before(time.Now()) {
		s.writeError(w, http.StatusForbidden, "expired request token")
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

	user, err := s.ctrl.UserAuthenticate(params.Username, params.Password)
	if err != nil {
		s.log.Errorln(err)

		s.redirectError(w, u, map[string]string{
			"error":             "access_denied",
			"error_description": "user authentication failed",
		})

		return
	}

	if !funk.Every(user.Permissions, wrap(req.Scope)...) {
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

	session.Values["state"] = &types.Session{
		ID:        sessionID,
		ClientID:  req.ClientID,
		Subject:   user.Profile.Sub,
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

	authCode := &types.AuthCode{
		AuthRequest:       *req,
		Subject:           user.Profile.Sub,
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
	if !funk.Contains(app.AllowedGrants, "authorization_code") {
		s.writeError(w, http.StatusForbidden, "authorization_code grant not permitted")
		return
	}

	if params.RedirectURI == nil {
		params.RedirectURI = &app.RedirectUris[0]
	}

	// ensure the redirect uri is allowed
	if !funk.Contains(app.RedirectUris, *params.RedirectURI) {
		s.writeError(w, http.StatusForbidden, "unauthorized redirect uri")
		return
	}

	// all errors should go to the redirect uri
	u, err := url.Parse(*params.RedirectURI)
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, err)
		return
	}

	if params.LoginURI == nil {
		params.LoginURI = &app.LoginUris[0]
	}

	// ensure the login uri is allowed
	if !funk.Contains(app.LoginUris, *params.LoginURI) {
		s.log.Errorln(err)

		s.redirectError(w, u, map[string]string{
			"error":             "access_denied",
			"error_description": "unauthorized login uri",
		})

		return
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

	// check the scope against the app and audience
	if !checkScope(params.Scope, app.Permissions, aud.Permissions) {
		s.redirectError(w, u, map[string]string{
			"error":             "access_denied",
			"error_description": "insufficient permissions",
		})

		return
	}

	req := &types.AuthRequest{
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

		authCode := &types.AuthCode{
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
	} else {
		if err := s.destroySession(w, r); err != nil {
			s.log.Errorln(err)

			s.redirectError(w, u, map[string]string{
				"error":             "server_error",
				"error_description": err.Error(),
			})

			return
		}
	}

	u, err = url.Parse(*params.LoginURI)
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

	bearer := &types.BearerToken{
		TokenType: "bearer",
	}

	if !funk.Contains(app.AllowedGrants, params.GrantType) {
		s.writeError(w, http.StatusForbidden, "unauthorized grant")
		return
	}

	var aud *types.Audience

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

	var code *types.AuthCode

	switch params.GrantType {
	case oauth.GrantTypeClientCredentials:
		if params.ClientSecret == nil || *params.ClientSecret != app.ClientSecret {
			s.writeError(w, http.StatusForbidden, "bad client secret")
			return
		}

		if !funk.Every(app.Permissions, wrap(params.Scope)...) {
			s.writeError(w, http.StatusForbidden, "bad scope")
			return
		}

		if params.Audience == nil {
			s.writeError(w, http.StatusForbidden, "missing audience")
			return
		}

		// ensure the audience
		aud, err = s.ctrl.AudienceGet(*params.Audience)
		if err != nil {
			s.log.Errorln(err)

			s.writeErr(w, http.StatusBadRequest, err)
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
			s.writeError(w, http.StatusForbidden, "invalid refresh token")
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
			s.writeError(w, http.StatusForbidden, "token validation failed")
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
				s.writeError(w, http.StatusForbidden, "invalid code")
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
			s.writeError(w, http.StatusForbidden, "session does not exist")
			return
		}

		user, err := s.ctrl.UserGet(state.Subject)
		if err != nil {
			s.log.Errorln(err)

			s.writeError(w, http.StatusForbidden, err.Error())
			return
		}

		// check the scope against the code
		if !funk.Every(code.Scope, wrap(params.Scope)...) {
			s.writeError(w, http.StatusForbidden, "invalid scope")

			return
		}

		// check the scope against the app, audience and user permissions
		if !checkScope(params.Scope, app.Permissions, aud.Permissions, user.Permissions) {
			s.writeError(w, http.StatusForbidden, "invalid scope")

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
		if funk.Contains(params.Scope, oauth.ScopeOffline) {
			if params.RefreshNonce == nil || code.RefreshNonce == *params.RefreshNonce {
				s.writeError(w, http.StatusForbidden, "invalid refresh nonce")
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
		if funk.Contains(params.Scope, oauth.ScopeOpenID) {
			claims := jwt.MapClaims{
				"iat":       time.Now().Unix(),
				"auth_time": state.CreatedAt,
				"aud":       aud.Name,
				"sub":       state.Subject,
				"exp":       time.Now().Add(time.Duration(app.TokenLifetime)).Unix(),
				"azp":       state.ID,
				"name":      user.Profile.Name,
			}

			if funk.Contains(params.Scope, oauth.ScopeProfile) {
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
		s.writeError(w, http.StatusForbidden, "invalid grant type")
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

	if params.LogoutURI == nil {
		params.LogoutURI = &app.LogoutUris[0]
	}

	// ensure the redirect uri is allowed
	if !funk.Contains(app.LogoutUris, *params.LogoutURI) {
		s.writeError(w, http.StatusForbidden, "unauthorized log out uri")
		return
	}

	u, err := url.Parse(*params.LogoutURI)
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, err)
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
	token, err := s.AuthorizeRequest(r, []string{"openid", "profile"})
	if err != nil {
		s.writeErr(w, http.StatusForbidden, err)
		return
	}

	_, state, err := s.getSession(r)
	if err != nil {
		s.log.Errorln(err)

		s.writeErr(w, http.StatusInternalServerError, err)
		return
	}

	if state.ID == "" {
		s.writeError(w, http.StatusForbidden, "session does not exist")
		return
	}

	if token.Claims.(jwt.MapClaims)["sub"].(string) != state.Subject {
		s.writeError(w, http.StatusForbidden, "access denied")
		return
	}

	user, err := s.ctrl.UserGet(state.Subject)
	if err != nil {
		s.log.Errorln(err)

		s.writeErr(w, http.StatusInternalServerError, err)
		return
	}

	s.writeJSON(w, http.StatusOK, user.Profile, true)
}

func (s *Server) getSession(r *http.Request) (*sessions.Session, *types.Session, error) {
	c, err := s.sessions.Get(r, s.sessionCookie)
	if err != nil {
		return nil, nil, err
	}

	// check the session activity timeout
	val, ok := c.Values["timeout"]
	if !ok {
		return c, &types.Session{}, nil
	}

	// ensure the token
	to, ok := val.(sessionToken)
	if ok {
		if time.Unix(to.Timeout, 0).Before(time.Now()) {
			return c, &types.Session{}, nil
		}
	} else {
		return c, &types.Session{}, nil
	}

	// check for the state
	val, ok = c.Values["state"]
	if !ok {
		return c, &types.Session{}, nil
	}

	// ensure the session object
	state, ok := val.(types.Session)
	if !ok {
		return c, &types.Session{}, nil
	}

	// sanity check the token and the state
	if state.ID != to.SessionID {
		return c, &types.Session{}, nil
	}

	// sanity check the session expiration
	if time.Unix(state.ExpiresAt, 0).Before(time.Now()) {
		return c, &types.Session{}, nil
	}

	return c, &state, nil
}

func (s *Server) destroySession(w http.ResponseWriter, r *http.Request) error {
	c, err := s.sessions.Get(r, s.sessionCookie)
	if err != nil {
		return err
	}

	c.Values["state"] = &types.Session{}
	c.Values["timeout"] = &sessionToken{}
	c.Options.MaxAge = -1

	return c.Save(r, w)
}
