package snmp3

import "context"

type NotificationReceiver interface {
	ProcessPDU(context.Context, *Packet) error
}
