package snmp3

import (
	"context"
	"encoding/asn1"
	"errors"
	"fmt"
	"net"
)

type Dispatcher struct {
	MaxRecvSize int64
	mpm         *MessageProcessingModel

	notificationReceiver NotificationReceiver
}

func NewDispatcher(mpm *MessageProcessingModel) *Dispatcher {
	return &Dispatcher{
		MaxRecvSize: defaultMaxRecvSize,
		mpm:         mpm,
	}
}

const defaultMaxRecvSize = 2 * 1 << 10

func (d *Dispatcher) Listen(ctx context.Context, c net.PacketConn) error {
	defer c.Close()
	buf := make([]byte, d.MaxRecvSize)
	for {
		l, _, err := c.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) {
				if ne.Temporary() {
					continue
				}
			}
			return err
		}
		data := make([]byte, l)
		copy(data, buf[:l])
		if err := checkVersion(data); err != nil {
			return err
		}
		go func() {
			pdu, err := d.mpm.PrepareDataElements(data)
			if err != nil {
				fmt.Println(err)
				return
			}
			switch pdu.typ {
			case PDUTypeSNMPV2Trap:
				pduData, ok := pdu.Data.(*PDU)
				if !ok {
					// TODO: impl
				}
				d.notificationReceiver.ProcessPDU(context.Background(), pduData)
			}
		}()
	}
}

func checkVersion(data []byte) error {
	var whole asn1.RawValue
	if _, err := asn1.Unmarshal(data, &whole); err != nil {
		return err
	}

	var version int
	if _, err := asn1.Unmarshal(whole.Bytes, &version); err != nil {
		return err
	}

	if version != 3 {
		return errors.New("this SNMP version is not implemented")
	}
	return nil
}
