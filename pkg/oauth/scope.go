/*
 * Copyright (C) 2020 Atomic Media Foundation
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file in the root of this
 * workspace for details.
 */

package oauth

import "context"

// Scope returns specified scopes as a Permissions type
func Scope(s ...string) Permissions {
	return Permissions(s)
}

// Contains return true if the scope contains the value
func (s Permissions) Contains(value string) bool {
	for _, v := range s {
		if v == value {
			return true
		}
	}

	return false
}

// Every returns true if every element is contained in the scope
func (s Permissions) Every(elements ...string) bool {
	for _, elem := range elements {
		if !s.Contains(elem) {
			return false
		}
	}
	return true
}

// Some returns true if at least one of the elements is contained in the scope
func (s Permissions) Some(elements ...string) bool {
	for _, elem := range elements {
		if s.Contains(elem) {
			return true
		}
	}
	return false
}

// Without returns the scope excluding the elements
func (s Permissions) Without(elements ...string) Permissions {
	r := make(Permissions, 0)
	for _, v := range s {
		if !Permissions(elements).Contains(v) {
			r = append(r, v)
		}
	}

	return r
}

// CurrentRoles returns the user roles in the given context
func (u User) CurrentRoles(ctx context.Context) Permissions {
	if len(u.Roles) == 0 {
		return Permissions{}
	}

	octx := GetContext(ctx)

	if octx.Audience == nil {
		return Permissions{}
	}

	if p, ok := u.Roles[octx.Audience.Name]; ok {
		return p
	}

	return Permissions{}
}

// HasRole returns true if the user has the roles
func (u User) HasRole(ctx context.Context, role ...string) bool {
	return u.CurrentRoles(ctx).Every(role...)
}
