/*
 * Copyright (C) 2020 Atomic Media Foundation
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file in the root of this
 * workspace for details.
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
