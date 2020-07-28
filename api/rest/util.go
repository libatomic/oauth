/*
 * Copyright (C) 2020 Atomic Media Foundation
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file in the root of this
 * workspace for details.
 */

package rest

func safestr(s *string) string {
	if s == nil {
		return ""
	}

	return *s
}
