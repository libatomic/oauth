/*
 * Copyright (C) 2020 Atomic Media Foundation
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file in the root of this
 * workspace for details.
 */

package rest

import (
	"fmt"
	"net/http"

	"github.com/blang/semver/v4"
)

const (
	// Name the server name
	Name = "libatomic-oauth"

	// Version is the binary version
	Version = "1.0.0"
)

var (
	apiVer semver.Version
)

func init() {
	apiVer, _ = semver.Make(Version)
}

func versionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", fmt.Sprintf("%s/%s", Name, Version))

		next.ServeHTTP(w, r)
	})
}
