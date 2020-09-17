/*
 * Copyright (C) 2020 Atomic Media Foundation
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file in the root of this
 * workspace for details.
 */

package oauth

import (
	"context"

	"github.com/dgrijalva/jwt-go"
)

type (
	authContext struct {
		app   *Application
		aud   *Audience
		user  *User
		prin  interface{}
		token *jwt.Token
		req   *AuthRequest
		ctx   context.Context
	}

	// ContextOption defines a context option method
	ContextOption func(*authContext)
)

// BuildContext returns a new context from the paramters
func BuildContext(opts ...ContextOption) Context {
	ctx := &authContext{
		ctx: context.Background(),
	}

	for _, opt := range opts {
		opt(ctx)
	}

	return ctx
}

// WithApplication is used to build a context with the specified application
func WithApplication(app *Application) ContextOption {
	return func(a *authContext) {
		a.app = app
	}
}

// WithAudience is used to build a context with the specified audience
func WithAudience(aud *Audience) ContextOption {
	return func(a *authContext) {
		a.aud = aud
	}
}

// WithUser is used to build a context with the specified user
func WithUser(user *User) ContextOption {
	return func(a *authContext) {
		a.user = user
	}
}

// WithPrincipal is used to build a context with the specified principal
func WithPrincipal(prin interface{}) ContextOption {
	return func(a *authContext) {
		a.prin = prin
	}
}

// WithToken is used to build a context with the specified token
func WithToken(token *jwt.Token) ContextOption {
	return func(a *authContext) {
		a.token = token
	}
}

// WithRequest is used to build a context with the specified request
func WithRequest(req *AuthRequest) ContextOption {
	return func(a *authContext) {
		a.req = req
	}
}

// WithContext sets the internal context object
func WithContext(ctx context.Context) ContextOption {
	return func(a *authContext) {
		a.ctx = ctx
	}
}

// ContextFromRequest will create a context from the Controller and AuthRequest
func ContextFromRequest(ctx context.Context, ctrl Controller, req *AuthRequest) (Context, error) {
	aud, err := ctrl.AudienceGet(ctx, req.Audience)
	if err != nil {
		return nil, err
	}

	app, err := ctrl.ApplicationGet(ctx, req.ClientID)
	if err != nil {
		return nil, err
	}

	return &authContext{
		aud: aud,
		app: app,
		req: req,
	}, nil
}

func (c *authContext) User() *User {
	return c.user
}

func (c *authContext) Audience() *Audience {
	return c.aud
}

func (c *authContext) Application() *Application {
	return c.app
}

func (c *authContext) Principal() interface{} {
	return c.prin
}

func (c *authContext) Token() *jwt.Token {
	return c.token
}

func (c *authContext) Request() *AuthRequest {
	return c.req
}

func (c *authContext) Context() context.Context {
	return c.ctx
}
