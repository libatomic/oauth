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
	// Context is the oauth context
	Context struct {
		Application *Application
		Audience    *Audience
		User        *User
		Principal   interface{}
		Token       *jwt.Token
		Request     *AuthRequest
	}

	contextKey string
)

var (
	contextKeyContext contextKey = "oauth:context"
)

// NewContext returns a new context from the paramters
func NewContext(ctx context.Context, args ...interface{}) context.Context {
	octx := GetContext(ctx)

	for _, a := range args {
		switch t := a.(type) {
		case Context:
			return context.WithValue(ctx, contextKeyContext, &t)
		case *Context:
			return context.WithValue(ctx, contextKeyContext, t)
		case Application:
			octx.Application = &t
		case *Application:
			octx.Application = t
		case Audience:
			octx.Audience = &t
		case *Audience:
			octx.Audience = t
		case User:
			octx.User = &t
		case *User:
			octx.User = t
		case interface{}:
			octx.Principal = t
		case jwt.Token:
			octx.Token = &t
		case *jwt.Token:
			octx.Token = t
		}
	}

	return context.WithValue(ctx, contextKeyContext, octx)
}

// GetContext returns the context
func GetContext(ctx context.Context) *Context {
	auth, ok := ctx.Value(contextKeyContext).(*Context)
	if !ok {
		return &Context{}
	}
	return auth
}

// ContextFromRequest will create a context from the Controller and AuthRequest
func ContextFromRequest(ctx context.Context, ctrl Controller, req *AuthRequest) (context.Context, error) {
	aud, err := ctrl.AudienceGet(ctx, req.Audience)
	if err != nil {
		return nil, err
	}

	app, err := ctrl.ApplicationGet(NewContext(ctx, aud), req.ClientID)
	if err != nil {
		return nil, err
	}

	return NewContext(
		ctx,
		Context{
			Application: app,
			Audience:    aud,
			Request:     req,
		}), nil
}
