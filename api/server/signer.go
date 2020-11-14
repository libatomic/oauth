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

	"github.com/libatomic/oauth/pkg/oauth"
	"github.com/mitchellh/mapstructure"
)

func signValue(ctx context.Context, finalize func(context.Context, oauth.Claims) (string, error), val interface{}) (string, error) {
	claims := make(map[string]interface{})

	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		TagName: "json",
		Result:  &claims,
	})
	if err != nil {
		return "", err
	}
	if err := dec.Decode(val); err != nil {
		return "", err
	}

	token, err := finalize(ctx, oauth.Claims(claims))
	if err != nil {
		return "", err
	}

	return token, nil
}

func verifyValue(ctx context.Context, verify func(context.Context, string) (oauth.Claims, error), val string, out interface{}) error {
	claims, err := verify(ctx, val)
	if err != nil {
		return err
	}
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		TagName: "json",
		Result:  out,
	})
	if err != nil {
		return err
	}
	if err := dec.Decode(map[string]interface{}(claims)); err != nil {
		return err
	}
	return nil
}
