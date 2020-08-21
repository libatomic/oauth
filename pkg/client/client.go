/*
 * Copyright (C) 2020 Atomic Media Foundation
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file in the root of this
 * workspace for details.
 */

package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"

	"github.com/libatomic/oauth/pkg/oauth"
)

type (
	// Client is a client for the oauth library
	Client struct {
		client *http.Client

		host string

		scheme string

		basePath string

		clientID string

		clientSecret string
	}

	// Option is a client option method used to set proprties of the oauth client
	Option func(*Client)
)

// NewClient returns a new oauth client, the defaults are primarily for testing purposes
func NewClient(id, secret string, opts ...Option) *Client {
	const (
		defaultHost = "127.0.0.1:9000"

		defaultScheme = "http"

		defaultBasePath = "/oauth"
	)

	c := &Client{
		client:       http.DefaultClient,
		host:         defaultHost,
		scheme:       defaultScheme,
		basePath:     defaultBasePath,
		clientID:     id,
		clientSecret: secret,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// WithClient sets the http client for the carmack api client
func WithClient(h *http.Client) Option {
	return func(c *Client) {
		c.client = h
	}
}

// WithHost sets the host address
func WithHost(host string) Option {
	return func(c *Client) {
		c.host = host
	}
}

// WithScheme sets the client scheme
func WithScheme(scheme string) Option {
	return func(c *Client) {
		c.scheme = scheme
	}
}

// WithBasePath sets the client basepath
func WithBasePath(basePath string) Option {
	return func(c *Client) {
		c.basePath = basePath
	}
}

func (c *Client) path(p string) string {
	return fmt.Sprintf("%s://%s%s", c.scheme, c.host, path.Join(c.basePath, p))
}

func unmarshalError(data []byte) error {
	e := &oauth.ErrorResponse{}
	if err := json.Unmarshal(data, e); err != nil {
		return err
	}

	return errors.New(e.Message)
}
