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
	"encoding/json"
	"time"

	"github.com/golang/protobuf/ptypes"
	empty "github.com/golang/protobuf/ptypes/empty"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/libatomic/oauth/pkg/oauth"
	"github.com/ulule/deepcopier"
	"google.golang.org/protobuf/types/known/structpb"
)

type (
	// Server serves the oauth.Controller over rpc
	Server struct {
		ctrl oauth.Controller
	}
)

// AudienceGet implements the rpc.ServerController interface
func (s *Server) AudienceGet(ctx context.Context, in *AudienceGetInput) (*Audience, error) {
	aud, err := s.ctrl.AudienceGet(ctx, in.GetName())
	if err != nil {
		return nil, err
	}

	return &Audience{
		Name:           aud.Name,
		Description:    aud.Description,
		TokenAlgorithm: aud.TokenAlgorithm,
		TokenSecret:    aud.TokenSecret,
		Permissions:    []string(aud.Permissions),
	}, nil
}

// ApplicationGet implements the rpc.ServerController interface
func (s *Server) ApplicationGet(ctx context.Context, in *ApplicationGetInput) (*Application, error) {
	app, err := s.ctrl.ApplicationGet(ctx, in.GetID())
	if err != nil {
		return nil, err
	}

	rval := &Application{
		Name:          app.Name,
		Description:   *app.Description,
		ClientID:      app.ClientID,
		ClientSecret:  app.ClientSecret,
		Type:          app.Type,
		TokenLifetime: app.TokenLifetime,
		AllowedGrants: make([]*PermissionSet, 0),
		AppUris:       make([]*PermissionSet, 0),
		RedirectUris:  make([]*PermissionSet, 0),
		Permissions:   make([]*PermissionSet, 0),
	}

	for a, p := range app.AllowedGrants {
		rval.AllowedGrants = append(rval.AllowedGrants, &PermissionSet{
			Audience:    a,
			Permissions: []string(p),
		})
	}

	for a, p := range app.AppUris {
		rval.AppUris = append(rval.AppUris, &PermissionSet{
			Audience:    a,
			Permissions: []string(p),
		})
	}

	for a, p := range app.RedirectUris {
		rval.RedirectUris = append(rval.RedirectUris, &PermissionSet{
			Audience:    a,
			Permissions: []string(p),
		})
	}

	for a, p := range app.Permissions {
		rval.Permissions = append(rval.Permissions, &PermissionSet{
			Audience:    a,
			Permissions: []string(p),
		})
	}

	return rval, nil
}

// UserGet implements the rpc.ServerController interface
func (s *Server) UserGet(ctx context.Context, in *UserGetInput) (*User, error) {
	user, prin, err := s.ctrl.UserGet(ctx, in.GetID())
	if err != nil {
		return nil, err
	}

	var expiresAt *timestamp.Timestamp

	if !time.Time(user.PasswordExpiresAt).IsZero() {
		expiresAt, err = ptypes.TimestampProto(time.Time(user.PasswordExpiresAt))
		if err != nil {
			return nil, err
		}
	}

	var profile *Profile

	if user.Profile != nil {
		profile = &Profile{}
		deepcopier.Copy(user.Profile).To(profile)
	}

	data, err := json.Marshal(prin)
	if err != nil {
		return nil, err
	}

	rval := &User{
		Login:             user.Login,
		PasswordExpiresAt: expiresAt,
		Profile:           profile,
		Roles:             make([]*PermissionSet, 0),
		Permissions:       make([]*PermissionSet, 0),
		Principal:         data,
	}

	for a, p := range user.Roles {
		rval.Roles = append(rval.Roles, &PermissionSet{
			Audience:    a,
			Permissions: []string(p),
		})
	}

	for a, p := range user.Permissions {
		rval.Permissions = append(rval.Permissions, &PermissionSet{
			Audience:    a,
			Permissions: []string(p),
		})
	}

	return rval, nil
}

// UserAuthenticate implements the rpc.ServerController interface
func (s *Server) UserAuthenticate(ctx context.Context, in *UserAuthenticateInput) (*User, error) {
	user, prin, err := s.ctrl.UserAuthenticate(ctx, in.GetLogin(), in.GetPassword())
	if err != nil {
		return nil, err
	}

	var expiresAt *timestamp.Timestamp

	if !time.Time(user.PasswordExpiresAt).IsZero() {
		expiresAt, err = ptypes.TimestampProto(time.Time(user.PasswordExpiresAt))
		if err != nil {
			return nil, err
		}
	}

	var profile *Profile

	if user.Profile != nil {
		profile = &Profile{}
		deepcopier.Copy(user.Profile).To(profile)
	}

	data, err := json.Marshal(prin)
	if err != nil {
		return nil, err
	}

	rval := &User{
		Login:             user.Login,
		PasswordExpiresAt: expiresAt,
		Profile:           profile,
		Roles:             make([]*PermissionSet, 0),
		Permissions:       make([]*PermissionSet, 0),
		Principal:         data,
	}

	for a, p := range user.Roles {
		rval.Roles = append(rval.Roles, &PermissionSet{
			Audience:    a,
			Permissions: []string(p),
		})
	}

	for a, p := range user.Permissions {
		rval.Permissions = append(rval.Permissions, &PermissionSet{
			Audience:    a,
			Permissions: []string(p),
		})
	}

	return rval, nil
}

// UserCreate implements the rpc.ServerController interface
func (s *Server) UserCreate(ctx context.Context, in *UserCreateInput) (*User, error) {
	var profile *oauth.Profile

	if in.Profile != nil {
		profile = &oauth.Profile{}
		deepcopier.Copy(in.Profile).To(profile)
	}

	user, err := s.ctrl.UserCreate(ctx, in.Login, in.Password, profile, in.InviteCode)
	if err != nil {
		return nil, err
	}

	rval := &User{
		Login:       user.Login,
		Profile:     in.Profile,
		Roles:       make([]*PermissionSet, 0),
		Permissions: make([]*PermissionSet, 0),
	}

	for a, p := range user.Roles {
		rval.Roles = append(rval.Roles, &PermissionSet{
			Audience:    a,
			Permissions: []string(p),
		})
	}

	for a, p := range user.Permissions {
		rval.Permissions = append(rval.Permissions, &PermissionSet{
			Audience:    a,
			Permissions: []string(p),
		})
	}

	return nil, nil
}

// UserUpdate implements the rpc.ServerController interface
func (s *Server) UserUpdate(ctx context.Context, in *UserUpdateInput) (*empty.Empty, error) {

	if in.Profile != nil {
		var profile oauth.Profile

		deepcopier.Copy(in.Profile).To(&profile)

		if err := s.ctrl.UserUpdate(ctx, in.GetID(), &profile); err != nil {
			return nil, err
		}
	}

	return &empty.Empty{}, nil
}

// TokenFinalize implements the rpc.ServerController interface
func (s *Server) TokenFinalize(ctx context.Context, in *Token) (*BearerToken, error) {
	claims := oauth.Claims(in.Claims.AsMap())

	bearer, err := s.ctrl.TokenFinalize(ctx, claims)
	if err != nil {
		return nil, err
	}

	return &BearerToken{
		Token: bearer,
	}, nil
}

// TokenValidate implements the rpc.ServerController interface
func (s *Server) TokenValidate(ctx context.Context, in *BearerToken) (*Token, error) {

	claims, err := s.ctrl.TokenValidate(ctx, in.Token)
	if err != nil {
		return nil, err
	}

	c, err := structpb.NewStruct(map[string]interface{}(claims))
	if err != nil {
		return nil, err
	}

	return &Token{
		Claims: c,
	}, nil

}
