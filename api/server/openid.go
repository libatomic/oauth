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
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"fmt"
	"net/http"
	"path"

	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/oauth/pkg/oauth"
	"gopkg.in/square/go-jose.v2"
)

type (
	// OIDConfigInput is the input for the jwks route
	OIDConfigInput struct {
	}

	// JWKSInput is the input for the jwks route
	JWKSInput struct {
	}
)

func init() {
	registerRoutes([]route{
		{"/.well-known/openid-configuration", http.MethodGet, &OIDConfigInput{}, openidConfig, nil, nil},
		{"/.well-known/jwks.json", http.MethodGet, &JWKSInput{}, jwks, nil, nil},
	})
}

func issuer(ctx context.Context) oauth.URI {
	r, _ := api.Request(ctx)

	iss := oauth.URI(
		fmt.Sprintf("https://%s%s",
			r.Host,
			path.Clean(path.Dir(r.URL.Path))),
	)

	return iss
}

func openidConfig(ctx context.Context, params *OIDConfigInput) api.Responder {
	ctrl := oauth.AuthContext(ctx).Controller

	aud, err := ctrl.AudienceGet(ctx, api.RequestHost(ctx))
	if err != nil {
		return oauth.Errorf(oauth.ErrorCodeInvalidRequest, "audience lookup failed: %s", err)
	}

	iss := issuer(ctx)

	config := struct {
		Issuer                 oauth.URI `json:"issuer"`
		JWKSURI                oauth.URI `json:"jwks_uri"`
		AuthorizationEndpoint  oauth.URI `json:"authorization_endpoint"`
		ResponseTypesSupported []string  `json:"response_type_supported"`
		SubjectTypesSupported  []string  `json:"subject_types_supported"`
		SigningAlgSupported    []string  `json:"id_token_signing_alg_values_supported"`
		TokenEndpoint          oauth.URI `json:"token_endpoint"`
		UserInfoEndpoint       oauth.URI `json:"userinfo_endpoint"`
		EndSessionEndpoint     oauth.URI `json:"end_session_endpoint"`
		GrantTypesSupported    []string  `json:"grant_types_supported"`
		IntrospectionEndpoint  oauth.URI `json:"introspection_endpoint"`
		RevocationEndpoint     oauth.URI `json:"revocation_endpoint"`
		ScopesSupported        []string  `json:"scopes_supported"`
		CodeChallengeMethods   []string  `json:"code_challenge_methods_supported,omitempty"`
	}{
		Issuer:                 iss.Append("..", "oauth"),
		JWKSURI:                iss.Append(".well-known/jwks.json"),
		AuthorizationEndpoint:  iss.Append("authorize"),
		ResponseTypesSupported: []string{"code"},
		SubjectTypesSupported:  []string{"public"},
		SigningAlgSupported:    []string{"RS256", "HS256"},
		TokenEndpoint:          iss.Append("token"),
		UserInfoEndpoint:       iss.Append("userInfo"),
		EndSessionEndpoint:     iss.Append("logout"),
		IntrospectionEndpoint:  iss.Append("token-introspect"),
		RevocationEndpoint:     iss.Append("token-revoke"),
		GrantTypesSupported: []string{
			oauth.GrantTypeAuthCode,
			oauth.GrantTypeClientCredentials,
			oauth.GrantTypeRefreshToken,
		},
		ScopesSupported:      aud.Permissions(),
		CodeChallengeMethods: []string{"S256"},
	}

	return api.NewResponse(config)
}

func jwks(ctx context.Context, params *JWKSInput) api.Responder {
	ctrl := oauth.AuthContext(ctx).Controller

	keys := make([]jose.JSONWebKey, 0)

	aud, err := ctrl.AudienceGet(ctx, api.RequestHost(ctx))
	if err != nil {
		return oauth.Errorf(oauth.ErrorCodeInvalidRequest, "audience lookup failed: %s", err)
	}

	if aud.TokenAlgorithm() != oauth.AudienceTokenAlgorithmRS256 {
		return oauth.Errorf(oauth.ErrorCodeInvalidRequest, "audience does not support rsa tokens")
	}

	cert, err := aud.VerifyCertificate()
	if err != nil {
		return oauth.Errorf(oauth.ErrorCodeInvalidRequest, "audience does not support rsa tokens: %s", err)
	}

	print := sha1.Sum(cert.Raw)

	key := jose.JSONWebKey{
		KeyID:                     aud.Name(),
		Key:                       aud.VerifyKey().(*rsa.PublicKey),
		Algorithm:                 aud.TokenAlgorithm(),
		Use:                       "sig",
		Certificates:              []*x509.Certificate{cert},
		CertificateThumbprintSHA1: print[:],
	}

	keys = append(keys, key)

	return api.NewResponse(jose.JSONWebKeySet{
		Keys: keys,
	})
}
