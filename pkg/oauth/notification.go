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

type (
	// Notification is a simply a notification interface
	Notification interface {
		Type() NotificationType
		Subject() string
		Channels() NotificationChannels
		URI() *URI
	}

	// NotificationType is a notification type
	NotificationType string

	// NotificationChannel is the channel to notify
	NotificationChannel string

	// NotificationChannels is an array of notifications
	NotificationChannels []NotificationChannel
)

const (
	// NotificationTypeVerify are verification notifications
	NotificationTypeVerify NotificationType = "verify"

	// NotificationTypeSignup are signup notifications
	NotificationTypeSignup NotificationType = "signup"

	// NotificationTypePassword are password notification
	NotificationTypePassword NotificationType = "password"

	// NotificationTypePasswordReset are password reset notification
	NotificationTypePasswordReset NotificationType = "password-reset"

	// NotificationTypeInvite are invitation notification
	NotificationTypeInvite NotificationType = "invite"

	// NotificationChannelEmail is an email notification
	NotificationChannelEmail NotificationChannel = "email"

	// NotificationChannelPhone is an sms notification
	NotificationChannelPhone NotificationChannel = "phone"
)

// Contains returns if the channel
func (n NotificationChannels) Contains(value NotificationChannel) bool {
	for _, v := range n {
		if v == value {
			return true
		}
	}

	return false
}

func (n NotificationType) String() string {
	return string(n)
}
