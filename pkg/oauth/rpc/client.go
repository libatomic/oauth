//
// This file is part of the Atomic Stack (https://github.com/libatomic/atomic).
// Copyright (c) 2020 Atomic Publishing.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package rpc

import (
	context "context"

	"github.com/go-openapi/strfmt"
	"github.com/libatomic/oauth/pkg/oauth"
	"github.com/ulule/deepcopier"
	"google.golang.org/grpc"
)

type (
	// Client implements the oauth.Controller interface around an rpc client
	Client struct {
		client ControllerClient
	}
)

// NewClient returns a new client controller
func NewClient(conn *grpc.ClientConn) oauth.Controller {
	return &Client{
		client: NewControllerClient(conn),
	}
}

// AudienceGet implements the oauth.Contoller interface
func (c *Client) AudienceGet(ctx context.Context, name string) (*oauth.Audience, error) {
	aud, err := c.client.AudienceGet(ctx, &AudienceGetInput{
		Name: name,
	})
	if err != nil {
		return nil, err
	}
	return &oauth.Audience{
		Name:           aud.Name,
		Description:    aud.Description,
		TokenAlgorithm: aud.TokenAlgorithm,
		TokenLifetime:  aud.TokenLifetime,
		TokenSecret:    aud.TokenSecret,
		Permissions:    oauth.Permissions(aud.Permissions),
	}, nil
}

// ApplicationGet implements the oauth.Contoller interface
func (c *Client) ApplicationGet(ctx context.Context, id string) (*oauth.Application, error) {
	app, err := c.client.ApplicationGet(ctx, &ApplicationGetInput{
		ID: id,
	})
	if err != nil {
		return nil, err
	}

	rval := &oauth.Application{
		Name:          app.Name,
		Description:   &app.Description,
		ClientID:      app.ClientID,
		ClientSecret:  app.ClientSecret,
		TokenLifetime: app.TokenLifetime,
		Type:          app.Type,
		AllowedGrants: make(oauth.PermissionSet),
		RedirectUris:  make(oauth.PermissionSet),
		AppUris:       make(oauth.PermissionSet),
		Permissions:   make(oauth.PermissionSet),
	}

	for _, p := range app.AllowedGrants {
		rval.AllowedGrants[p.Audience] = oauth.Permissions(p.Permissions)
	}

	for _, p := range app.RedirectUris {
		rval.RedirectUris[p.Audience] = oauth.Permissions(p.Permissions)
	}

	for _, p := range app.AppUris {
		rval.AppUris[p.Audience] = oauth.Permissions(p.Permissions)
	}

	for _, p := range app.Permissions {
		rval.Permissions[p.Audience] = oauth.Permissions(p.Permissions)
	}

	return rval, nil
}

// UserGet implements the oauth.Contoller interface
func (c *Client) UserGet(ctx context.Context, id string) (*oauth.User, interface{}, error) {
	arg := &UserGetInput_ID{
		ID: id,
	}

	result, err := c.client.UserGet(ctx, &UserGetInput{
		UserGet: arg,
	})
	if err != nil {
		return nil, nil, err
	}

	var profile *oauth.Profile

	if result.Profile != nil {
		deepcopier.Copy(result.Profile).To(profile)
	}

	user := &oauth.User{
		Login:             result.Login,
		PasswordExpiresAt: strfmt.DateTime(result.PasswordExpiresAt.AsTime()),
		Roles:             make(oauth.PermissionSet),
		Permissions:       make(oauth.PermissionSet),
		Profile:           profile,
	}

	for _, p := range result.Roles {
		user.Roles[p.Audience] = oauth.Permissions(p.Permissions)
	}

	for _, p := range result.Roles {
		user.Permissions[p.Audience] = oauth.Permissions(p.Permissions)
	}

	return user, nil, nil
}

// UserAuthenticate implements the oauth.Contoller interface
func (c *Client) UserAuthenticate(ctx context.Context, login string, password string) (*oauth.User, interface{}, error) {

	return nil, nil, nil
}

// UserCreate implements the oauth.Contoller interface
func (c *Client) UserCreate(ctx context.Context, user oauth.User, password string, invite ...string) (*oauth.User, error) {
	return nil, nil
}

// UserUpdate implements the oauth.Contoller interface
func (c *Client) UserUpdate(ctx context.Context, user *oauth.User) error {
	return nil
}

// UserResetPassword implements the oauth.Contoller interface
func (c *Client) UserResetPassword(ctx context.Context, login string, resetCode string) error {
	return nil
}

// UserSetPassword implements the oauth.Contoller interface
func (c *Client) UserSetPassword(ctx context.Context, id string, password string) error {
	return nil
}

// TokenFinalize implements the oauth.Contoller interface
func (c *Client) TokenFinalize(ctx context.Context, scope oauth.Permissions, claims map[string]interface{}) {

}
