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
 
package server client

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
