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
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/libatomic/oauth/pkg/oauth"
)

// Token returns a client credentials token
func (c *Client) Token(scope oauth.Permissions, audience string) (*oauth.BearerToken, error) {
	form := url.Values{}
	form.Add("client_id", c.clientID)
	form.Add("client_secret", c.clientSecret)
	form.Add("grant_type", oauth.GrantTypeClientCredentials)
	form.Add("audience", audience)
	form.Add("scope", strings.Join(scope, " "))

	req, err := http.NewRequest("POST", c.path("/token"), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if status := res.StatusCode; status != http.StatusOK {
		return nil, unmarshalError(data)
	}

	token := &oauth.BearerToken{}
	if err := json.Unmarshal(data, token); err != nil {
		return nil, err
	}

	return token, nil
}
