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

package oauth

import (
	"context"
)

type (
	// Context is the oauth context
	Context struct {
		Controller  Controller
		Application *Application
		Audience    Audience
		User        *User
		Principal   interface{}
		Token       Claims
		Bearer      string
		Request     *AuthRequest
		Error       error
	}

	contextKey string
)

var (
	contextKeyContext contextKey = "oauth:context"
)

// NewContext returns a new context from the paramters
func NewContext(ctx context.Context, args ...interface{}) context.Context {
	octx := *AuthContext(ctx)

	for _, a := range args {
		switch t := a.(type) {
		case Context:
			return context.WithValue(ctx, contextKeyContext, &t)
		case *Context:
			return context.WithValue(ctx, contextKeyContext, t)
		case Controller:
			octx.Controller = t
		case Application:
			octx.Application = &t
		case *Application:
			octx.Application = t
		case Audience:
			octx.Audience = t
		case User:
			octx.User = &t
		case *User:
			octx.User = t
		case Claims:
			octx.Token = t
		case error:
			octx.Error = t
		case interface{}:
			octx.Principal = t
		}
	}

	return context.WithValue(ctx, contextKeyContext, &octx)
}

// AuthContext returns the context
func AuthContext(ctx context.Context) *Context {
	auth, ok := ctx.Value(contextKeyContext).(*Context)
	if !ok {
		return &Context{}
	}

	if auth.Request == nil {
		auth.Request = &AuthRequest{}

		if auth.Audience != nil {
			auth.Request.Audience = auth.Audience.Name()
		}

		if auth.Application != nil {
			auth.Request.ClientID = auth.Application.ClientID
		}

		if auth.User != nil {
			auth.Request.Subject = &auth.User.Profile.Subject
		}

		auth.Request.Scope = auth.Token.Scope()
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
			Controller:  ctrl,
		}), nil
}
