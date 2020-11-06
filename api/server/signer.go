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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
)

func signValue(ctx context.Context, privKey *rsa.PrivateKey, key string, val interface{}) (string, error) {
	data, err := json.Marshal(val)
	if err != nil {
		return "", err
	}

	hashed := sha256.Sum256(data)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(data) + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func verifyValue(ctx context.Context, pubKey *rsa.PublicKey, key string, val string, out interface{}) error {
	parts := strings.Split(val, ".")
	msg, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return err
	}

	hashed := sha256.Sum256(msg)

	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}

	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], sig); err != nil {
		return err
	}

	return json.Unmarshal(msg, out)
}
