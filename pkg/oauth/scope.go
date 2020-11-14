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

	octx := AuthContext(ctx)

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
