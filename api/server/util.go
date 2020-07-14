/*
 * Copyright (C) 2020 Atomic Media Foundation
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file in the root of this
 * workspace for details.
 */

package server

func contains(in []string, value string) bool {
	for _, v := range in {
		if v == value {
			return true
		}
	}

	return false
}

func every(in []string, elements ...string) bool {
	for _, elem := range elements {
		if !contains(in, elem) {
			return false
		}
	}
	return true
}

func some(in []string, elements ...string) bool {
	for _, elem := range elements {
		if contains(in, elem) {
			return true
		}
	}
	return false
}

func without(in []string, elements ...string) []string {
	r := make([]string, 0)
	for _, v := range in {
		if !contains(elements, v) {
			r = append(r, v)
		}
	}

	return r
}
