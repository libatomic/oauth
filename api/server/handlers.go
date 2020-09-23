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
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-openapi/runtime"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/oauth/api/server/auth"
	"github.com/libatomic/oauth/api/server/user"
	"github.com/libatomic/oauth/pkg/oauth"

	"github.com/mitchellh/mapstructure"
	"github.com/mr-tron/base58"
)

const (
	// AuthRequestParam is the name of the request token parameter
	AuthRequestParam = "request_token"
)

type (
	sessionToken struct {
		Timeout   int64
		SessionID string
	}
)

func (s *Server) ensureURI(uri string, search []string) (*url.URL, error) {
	u, err := url.Parse(uri)
	if err != nil {
		s.Log().Error(err.Error())

		return nil, errors.New("unauthorized redirect uri")
	}

	for _, a := range search {
		if a == u.String() {
			return u, nil
		}

		uu, _ := url.Parse(a)
		if uu.Scheme == u.Scheme && u.Host == uu.Host && u.Path == uu.Path {
			return u, nil
		}
	}

	return nil, errors.New("unauthorized redirect uri")
}

func (s *Server) authorize(params *auth.AuthorizeParams) api.Responder {
	// ensure this is a valid application
	app, err := s.ctrl.ApplicationGet(params.Context(), params.ClientID)
	if err != nil {
		return api.Error(err).WithStatus(http.StatusBadRequest)
	}

	// enusure this app supports the authorization_code flow
	if !app.AllowedGrants.Contains("authorization_code") {
		return api.Errorf("authorization_code grant not permitted").WithStatus(http.StatusUnauthorized)
	}

	if params.RedirectURI == nil {
		params.RedirectURI = &app.RedirectUris[0]
	}

	// ensure the redirect uri path is allowed
	u, err := s.ensureURI(*params.RedirectURI, app.RedirectUris)
	if err != nil {
		return api.Errorf("unauthorized redirect uri").WithStatus(http.StatusUnauthorized)
	}

	if params.AppURI == nil {
		params.AppURI = &app.AppUris[0]
	}

	appURI, err := s.ensureURI(*params.AppURI, app.AppUris)
	if err != nil {
		return api.Redirect(u, map[string]string{
			"error":             "access_denied",
			"error_description": err.Error(),
		})
	}

	// ensure the audience
	aud, err := s.ctrl.AudienceGet(params.Context(), params.Audience)
	if err != nil {
		s.Log().Error(err.Error())

		return api.Redirect(u, map[string]string{
			"error":             "bad_request",
			"error_description": "invalid audience",
		})
	}

	if len(params.Scope) > 0 {
		// check the scope against the app and audience
		perms, ok := app.Permissions[params.Audience]
		if !ok || !perms.Every(params.Scope...) {
			return api.Redirect(u, map[string]string{
				"error":             "access_denied",
				"error_description": "insufficient permissions",
			})
		}

		// sanity check to ensure the audience actually has the permissions requested
		if !aud.Permissions.Every(params.Scope...) {
			return api.Redirect(u, map[string]string{
				"error":             "access_denied",
				"error_description": "insufficient permissions",
			})
		}
	}

	req := &oauth.AuthRequest{
		ClientID:            params.ClientID,
		RedirectURI:         *params.RedirectURI,
		Scope:               params.Scope,
		Audience:            params.Audience,
		UserPool:            params.UserPool,
		State:               params.State,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: *params.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(time.Minute * 10).Unix(),
	}

	rw, r := params.UnbindRequest()
	session, state, err := s.getSession(r)
	if err != nil {
		s.Log().Error(err.Error())

		return api.Redirect(u, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})
	}

	// if we already gave a session, use that to create the code
	if state.ID != "" {
		session.Values["state"] = state

		session.Values["timeout"] = &sessionToken{
			SessionID: state.ID,
			Timeout:   time.Now().Add(s.sessionTimeout).Unix(),
		}

		if err := session.Save(r, rw); err != nil {
			s.Log().Error(err.Error())

			return api.Redirect(u, map[string]string{
				"error":             "server_error",
				"error_description": err.Error(),
			})
		}

		authCode := &oauth.AuthCode{
			AuthRequest: *req,
			Subject:     state.Subject,
			SessionID:   session.ID,
		}
		if err := s.codes.CodeCreate(authCode); err != nil {
			s.Log().Error(err.Error())

			return api.Redirect(u, map[string]string{
				"error":             "server_error",
				"error_description": err.Error(),
			})
		}

		q := u.Query()

		q.Set("code", authCode.Code)

		if req.State != nil {
			q.Set("state", *req.State)
		}

		u.RawQuery = q.Encode()

		return api.Redirect(u)
	}

	if err := s.destroySession(r, rw); err != nil {
		s.Log().Error(err.Error())

		return api.Redirect(u, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})
	}

	token, err := s.cookie.Encode(AuthRequestParam, req)
	if err != nil {
		return api.Error(err).WithStatus(http.StatusInternalServerError)
	}

	q := appURI.Query()
	q.Set(AuthRequestParam, token)
	appURI.RawQuery = q.Encode()

	return api.Redirect(appURI)
}

func (s *Server) login(params *auth.LoginParams) api.Responder {
	req := &oauth.AuthRequest{}
	if err := s.cookie.Decode(AuthRequestParam, params.RequestToken, req); err != nil {
		return api.Error(err).WithStatus(http.StatusBadRequest)
	}

	if time.Unix(req.ExpiresAt, 0).Before(time.Now()) {
		return api.Errorf("expired request token").WithStatus(http.StatusUnauthorized)
	}

	u, _ := url.Parse(req.RedirectURI)

	// validate the code verifier
	verifier, err := base64.RawURLEncoding.DecodeString(params.CodeVerifier)
	if err != nil {
		s.Log().Error(err.Error())

		return api.Redirect(u, map[string]string{
			"error":             "invalid_request",
			"error_description": "invalid code_verifier",
		})
	}
	code := sha256.Sum256([]byte(verifier))

	// validate the code challenge
	chal, err := base64.RawURLEncoding.DecodeString(req.CodeChallenge)
	if err != nil {
		s.Log().Error(err.Error())

		return api.Redirect(u, map[string]string{
			"error":             "invalid_request",
			"error_description": "invalid code_challenge",
		})
	}

	// verify the code verifier against the challenge
	if !bytes.Equal(code[:], chal) {
		s.Log().Error(err.Error())

		return api.Redirect(u, map[string]string{
			"error":             "invalid_request",
			"error_description": "code verification failed",
		})
	}

	ctx, err := oauth.ContextFromRequest(params.Context(), s.ctrl, req)
	if err != nil {
		return api.Redirect(u, map[string]string{
			"error":             "invalid_request",
			"error_description": "context verification failed",
		})
	}

	user, _, err := s.ctrl.UserAuthenticate(ctx, params.Login, params.Password)
	if err != nil {
		s.Log().Error(err.Error())

		return api.Redirect(u, map[string]string{
			"error":             "access_denied",
			"error_description": "user authentication failed",
		})
	}

	perms, ok := user.Permissions[req.Audience]
	if !ok {
		return api.Redirect(u, map[string]string{
			"error":             "access_denied",
			"error_description": "user authorization failed",
		})
	}

	if len(req.Scope) == 0 {
		req.Scope = perms
	}

	if !perms.Every(req.Scope...) {
		return api.Redirect(u, map[string]string{
			"error":             "access_denied",
			"error_description": "user authorization failed",
		})
	}

	_, r := params.UnbindRequest()

	session, err := s.sessions.Get(r, s.sessionCookie)
	if err != nil {
		s.Log().Error(err.Error())

		return api.Redirect(u, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})
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

	rw, r := params.UnbindRequest()
	if err := session.Save(r, rw); err != nil {
		s.Log().Error(err.Error())

		return api.Redirect(u, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})
	}

	authCode := &oauth.AuthCode{
		AuthRequest:       *req,
		Subject:           user.Profile.Subject,
		SessionID:         session.ID,
		UserAuthenticated: true,
	}
	if err := s.codes.CodeCreate(authCode); err != nil {

		s.Log().Error(err.Error())

		return api.Redirect(u, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})
	}

	u, _ = url.Parse(req.RedirectURI)

	q := u.Query()

	q.Set("code", authCode.Code)

	if req.State != nil {
		q.Set("state", *req.State)
	}

	u.RawQuery = q.Encode()

	return api.Redirect(u)
}

func (s *Server) signup(params *auth.SignupParams) api.Responder {
	if !s.allowSignup && params.InviteCode == nil {
		return api.StatusErrorf(http.StatusUnauthorized, "user self-registration disabled")

	}

	req := &oauth.AuthRequest{}
	if err := s.cookie.Decode(AuthRequestParam, params.RequestToken, req); err != nil {
		return api.StatusError(http.StatusBadRequest, err)

	}

	if time.Unix(req.ExpiresAt, 0).Before(time.Now()) {
		return api.StatusErrorf(http.StatusUnauthorized, "expired request token")

	}

	ctx, err := oauth.ContextFromRequest(params.Context(), s.ctrl, req)
	if err != nil {
		return api.StatusError(http.StatusInternalServerError, err)
	}

	if _, err := s.ctrl.UserCreate(ctx, oauth.User{
		Login: params.Login,
		Profile: oauth.Profile{
			Name:  safestr(params.Name),
			Email: params.Email,
		},
	}, params.Password, safestr(params.InviteCode)); err != nil {
		return api.StatusError(http.StatusBadRequest, err)
	}

	rw, r := params.UnbindRequest()
	loginParams := &auth.LoginParams{
		CodeVerifier: params.CodeVerifier,

		Login: params.Login,

		Password: params.Password,

		RequestToken: params.RequestToken,
	}

	loginParams.BindRequest(rw, r, runtime.DiscardConsumer)

	return s.login(loginParams)
}

func (s *Server) publicKey(params *auth.PublicKeyGetParams) api.Responder {
	var aud *oauth.Audience
	var err error

	if params.Audience != nil {
		aud, err = s.ctrl.AudienceGet(params.Context(), *params.Audience)
		if err != nil {
			return api.StatusError(http.StatusBadRequest, err)
		}
	}

	pubKey, err := s.ctrl.TokenPublicKey(oauth.BuildContext(oauth.WithAudience(aud)))
	if err != nil {
		return api.StatusError(http.StatusInternalServerError, err)
	}

	// create the jwks output
	key, err := jwk.New(pubKey)
	if err != nil {
		return api.StatusError(http.StatusInternalServerError, err)

	}

	thumb, err := key.Thumbprint(crypto.SHA1)
	if err != nil {
		return api.StatusError(http.StatusInternalServerError, err)

	}

	// usw the thumbprint as kid and x5t
	key.Set("kid", hex.EncodeToString(thumb))
	key.Set("x5t", base64.RawURLEncoding.EncodeToString(thumb))

	key.Set("alg", "RS256")
	key.Set("use", "sig")

	keys := map[string]interface{}{
		"keys": []interface{}{key},
	}

	return api.NewResponse(keys)
}

func (s *Server) token(params *auth.TokenParams) api.Responder {
	// ensure this is a valid application
	app, err := s.ctrl.ApplicationGet(params.Context(), params.ClientID)
	if err != nil {
		return api.StatusError(http.StatusBadRequest, err)

	}

	bearer := &oauth.BearerToken{
		TokenType: "bearer",
	}

	if !app.AllowedGrants.Contains(params.GrantType) {
		return api.StatusErrorf(http.StatusUnauthorized, "unauthorized grant")

	}

	if params.Audience == nil {
		return api.StatusErrorf(http.StatusUnauthorized, "missing audience")

	}

	// ensure the audience
	aud, err := s.ctrl.AudienceGet(params.Context(), *params.Audience)
	if err != nil {
		s.Log().Error(err.Error())

		return api.StatusError(http.StatusBadRequest, err)

	}

	// sanity check to ensure the audience actually has the permissions requested
	if !aud.Permissions.Every(params.Scope...) {
		return api.StatusErrorf(http.StatusUnauthorized, "bad scope")

	}

	_, r := params.UnbindRequest()

	signToken := func(claims jwt.MapClaims, ctx oauth.Context) (string, error) {
		var token *jwt.Token
		var key interface{}

		claims["iss"] = fmt.Sprintf("https://%s%s", r.Host, path.Clean(path.Join(path.Dir(r.URL.Path), "/.well-known/jwks.json")))

		switch aud.TokenAlgorithm {
		case "RS256":
			signingKey, err := s.ctrl.TokenPrivateKey(ctx)
			if err != nil {
				return "", err
			}

			token = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			key = signingKey

		case "HS256":
			token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
			key = []byte(aud.TokenSecret)
		}
		return token.SignedString(key)
	}

	var code *oauth.AuthCode
	var user *oauth.User

	switch params.GrantType {
	case oauth.GrantTypePassword:
		if !s.allowPasswordGrant {
			return api.StatusErrorf(http.StatusUnauthorized, "invalid grant type")

		}

		if params.Username == nil || params.Password == nil {
			return api.StatusErrorf(http.StatusBadRequest, "bad request")

		}

		user, _, err = s.ctrl.UserAuthenticate(
			oauth.BuildContext(
				oauth.WithApplication(app),
				oauth.WithAudience(aud),
			),
			*params.Username,
			*params.Password,
		)
		if err != nil {
			return api.StatusErrorf(http.StatusUnauthorized, "not authorized")

		}

		if len(params.Scope) == 0 {
			params.Scope = user.Permissions[*params.Audience]
		}
		fallthrough

	case oauth.GrantTypeClientCredentials:
		if params.ClientSecret == nil || *params.ClientSecret != app.ClientSecret {
			return api.StatusErrorf(http.StatusUnauthorized, "bad client secret")

		}

		// ensure this app has these permissions
		perms, ok := app.Permissions[*params.Audience]
		if !ok || !perms.Every(params.Scope...) {
			return api.StatusErrorf(http.StatusUnauthorized, "bad scope")

		}

		claims := make(jwt.MapClaims)

		exp := time.Now().Add(time.Second * time.Duration(aud.TokenLifetime)).Unix()

		if user != nil {
			claims["sub"] = user.Profile.Subject
		} else {
			claims["sub"] = fmt.Sprintf("%s@applications", app.ClientID)
		}
		claims["aud"] = aud.Name
		claims["exp"] = exp
		claims["iat"] = time.Now().Unix()
		claims["scope"] = strings.Join(params.Scope, " ")

		ctx := oauth.BuildContext(
			oauth.WithApplication(app),
			oauth.WithAudience(aud),
		)
		s.ctrl.TokenFinalize(
			ctx,
			params.Scope,
			claims,
		)

		token, err := signToken(claims, ctx)
		if err != nil {
			return api.StatusError(http.StatusInternalServerError, err)

		}
		bearer.AccessToken = token
		bearer.ExpiresIn = int64(exp - time.Now().Unix())

	case oauth.GrantTypeRefreshToken:
		if params.RefreshToken == nil || params.RefreshVerifier == nil {
			return api.StatusErrorf(http.StatusBadRequest, "missing refresh token or verifier")
		}

		code, err = s.codes.CodeGet(*params.RefreshToken)
		if err != nil {
			return api.StatusErrorf(http.StatusUnauthorized, "invalid refresh token")
		}

		verifier, err := base64.RawURLEncoding.DecodeString(*params.RefreshVerifier)
		if err != nil {
			s.Log().Error(err.Error())

			return api.StatusError(http.StatusInternalServerError, err)
		}

		sum := sha256.Sum256(verifier)
		check := base64.RawURLEncoding.EncodeToString(sum[:])

		if code.RefreshNonce != check {
			return api.StatusErrorf(http.StatusUnauthorized, "token validation failed")
		}

		fallthrough

	case oauth.GrantTypeAuthCode:
		if code == nil {
			if params.Code == nil || params.CodeVerifier == nil {
				return api.StatusErrorf(http.StatusBadRequest, "missing code or verifier")
			}

			code, err = s.codes.CodeGet(*params.Code)
			if err != nil {
				return api.StatusErrorf(http.StatusUnauthorized, "invalid code")
			}

			verifier, err := base64.RawURLEncoding.DecodeString(*params.CodeVerifier)
			if err != nil {
				s.Log().Error(err.Error())

				return api.StatusError(http.StatusInternalServerError, err)
			}

			sum := sha256.Sum256(verifier)
			check := base64.RawURLEncoding.EncodeToString(sum[:])

			if code.CodeChallenge != check {
				s.Log().Error(err.Error())

				return api.StatusError(http.StatusInternalServerError, err)
			}
		}

		s.codes.CodeDestroy(code.Code)

		_, state, err := s.getSession(r)
		if err != nil {
			s.Log().Error(err.Error())

			return api.StatusError(http.StatusInternalServerError, err)
		}

		if state.ID == "" {
			state.Subject = code.Subject
			state.CreatedAt = code.IssuedAt
		}

		user, prin, err := s.ctrl.UserGet(
			oauth.BuildContext(
				oauth.WithApplication(app),
				oauth.WithAudience(aud),
				oauth.WithRequest(&code.AuthRequest),
			),
			state.Subject)
		if err != nil {
			s.Log().Error(err.Error())

			return api.StatusErrorf(http.StatusUnauthorized, err.Error())
		}

		perms, ok := user.Permissions[code.Audience]
		if len(params.Scope) == 0 {
			if len(code.Scope) == 0 {
				code.Scope = perms
			}
			params.Scope = code.Scope
		}

		// check the scope against the code
		if !ok || !code.Scope.Every(params.Scope...) {
			return api.StatusErrorf(http.StatusUnauthorized, "invalid request scope")
		}

		// ensure the app has access to this audience
		perms, ok = app.Permissions[aud.Name]
		// check the scope against the app, audience and user permissions
		if !ok || !perms.Every(params.Scope...) {
			return api.StatusErrorf(http.StatusUnauthorized, "invalid application scope")
		}

		// ensure the user has access to this audience
		perms, ok = user.Permissions[aud.Name]
		if !ok || !perms.Every(params.Scope...) {
			return api.StatusErrorf(http.StatusUnauthorized, "invalid user scope")
		}

		exp := time.Now().Add(time.Second * time.Duration(aud.TokenLifetime)).Unix()

		claims := jwt.MapClaims{
			"iat":   time.Now().Unix(),
			"aud":   aud.Name,
			"sub":   state.Subject,
			"scope": strings.Join(params.Scope, " "),
			"exp":   exp,
			"azp":   app.ClientID,
		}

		ctx := oauth.BuildContext(
			oauth.WithApplication(app),
			oauth.WithAudience(aud),
			oauth.WithUser(user),
			oauth.WithPrincipal(prin),
			oauth.WithRequest(&code.AuthRequest),
		)

		s.ctrl.TokenFinalize(
			ctx,
			params.Scope,
			claims,
		)

		token, err := signToken(claims, ctx)
		if err != nil {
			s.Log().Error(err.Error())

			return api.StatusError(http.StatusInternalServerError, err)
		}

		bearer.AccessToken = token
		bearer.ExpiresIn = int64(exp - time.Now().Unix())
		scope := oauth.Permissions(params.Scope)

		// check for offline_access
		if scope.Contains(oauth.ScopeOffline) {
			if params.RefreshNonce == nil {
				return api.StatusErrorf(http.StatusUnauthorized, "missing refresh nonce")
			}

			if code.RefreshNonce == *params.RefreshNonce {
				return api.StatusErrorf(http.StatusUnauthorized, "nonce reused")
			}
			code.RefreshNonce = *params.RefreshNonce

			code.ExpiresAt = time.Now().Add(s.sessionLifetime - s.sessionTimeout).Unix()

			if err := s.codes.CodeCreate(code); err != nil {
				s.Log().Error(err.Error())

				return api.StatusError(http.StatusInternalServerError, err)
			}

			bearer.RefreshToken = code.Code
		}

		// check for id token request
		if scope.Contains(oauth.ScopeOpenID) {
			claims := jwt.MapClaims{
				"iat":       time.Now().Unix(),
				"auth_time": state.CreatedAt,
				"aud":       aud.Name,
				"sub":       state.Subject,
				"exp":       time.Now().Add(time.Duration(app.TokenLifetime)).Unix(),
				"azp":       app.ClientID,
				"name":      user.Profile.Name,
			}

			if scope.Contains(oauth.ScopeProfile) {
				dec, _ := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
					TagName: "json",
					Result:  &claims,
				})

				if err := dec.Decode(user.Profile); err != nil {
					s.Log().Error(err.Error())

					return api.StatusError(http.StatusInternalServerError, err)
				}
			}

			token, err := signToken(claims, oauth.BuildContext(oauth.WithApplication(app), oauth.WithAudience(aud)))
			if err != nil {
				s.Log().Error(err.Error())

				return api.StatusError(http.StatusInternalServerError, err)
			}
			bearer.IDToken = token
		}

	default:
		return api.StatusErrorf(http.StatusUnauthorized, "invalid grant type")
	}

	return api.NewResponse(bearer)
}

func (s *Server) logout(params *auth.LogoutParams) api.Responder {
	// ensure this is a valid application
	app, err := s.ctrl.ApplicationGet(params.Context(), params.ClientID)
	if err != nil {
		return api.StatusError(http.StatusBadRequest, err)
	}

	if params.RedirectURI == nil {
		params.RedirectURI = &app.RedirectUris[0]
	}

	u, err := url.Parse(*params.RedirectURI)
	if err != nil {
		return api.StatusError(http.StatusBadRequest, err)

	}

	if params.RedirectURI == nil {
		params.RedirectURI = &app.RedirectUris[0]
	}

	if _, err := s.ensureURI(*params.RedirectURI, app.RedirectUris); err != nil {
		return api.StatusErrorf(http.StatusUnauthorized, "unauthorized logout uri")
	}

	rw, r := params.UnbindRequest()
	if err := s.destroySession(r, rw); err != nil {
		s.Log().Error(err.Error())

		api.Redirect(u, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})

	}

	q := u.Query()

	if params.State != nil {
		q.Set("state", *params.State)
	}

	u.RawQuery = q.Encode()

	return api.Redirect(u)
}

func (s *Server) userInfoUpdate(params *user.UserInfoUpdateParams, ctx oauth.Context) api.Responder {
	if ctx.User() == nil {
		return api.StatusErrorf(http.StatusUnauthorized, "invalid token")
	}

	user := ctx.User()
	user.Profile = params.Profile

	if err := s.ctrl.UserUpdate(ctx, user); err != nil {
		return api.StatusErrorf(http.StatusUnauthorized, "access denied")
	}

	return api.NewResponse(user.Profile)
}

func (s *Server) userInfo(params *user.UserInfoGetParams, ctx oauth.Context) api.Responder {
	if ctx.User() == nil {
		return api.StatusErrorf(http.StatusUnauthorized, "invalid token")
	}

	return api.NewResponse(ctx.User().Profile)
}

func (s *Server) userPrincipal(params *user.UserPrincipalGetParams, ctx oauth.Context) api.Responder {
	if ctx.Principal() == nil {
		return api.StatusErrorf(http.StatusUnauthorized, "invalid token")
	}

	return api.NewResponse(ctx.Principal())
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

func (s *Server) destroySession(r *http.Request, w http.ResponseWriter) error {
	c, err := s.sessions.Get(r, s.sessionCookie)
	if err != nil {
		return err
	}

	c.Values["state"] = &oauth.Session{}
	c.Values["timeout"] = &sessionToken{}
	c.Options.MaxAge = -1

	return c.Save(r, w)
}
