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

// Audience An audience is an API that applications can request permission to access on behalf of
// a user or itself.
type Audience interface {
	// The name of the audience. This is used in token request and token claims.
	Name() string

	// The audience description
	Description() string

	// permissions
	Permissions() Permissions

	// The audience token signing algorithm
	// Enum: [RS256 HS256]
	TokenAlgorithm() string

	// The lifetime for tokens created on behalf of this audience, in seconds
	TokenLifetime() int64

	// The signing secret used if the algorithm is HS256
	TokenSecret() string

	// Principal is the implementation specfic audience object
	Principal() interface{}
}

const (

	// AudienceTokenAlgorithmRS256 captures enum value "RS256"
	AudienceTokenAlgorithmRS256 string = "RS256"

	// AudienceTokenAlgorithmHS256 captures enum value "HS256"
	AudienceTokenAlgorithmHS256 string = "HS256"
)
