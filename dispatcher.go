package snmp3

import (
	"context"
	"errors"
	"fmt"
	"net"
)

type Dispatcher struct {
	MaxRecvSize int64
	mpm         *MessageProcessingModel
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
			fmt.Println(pdu)
			fmt.Println(pdu.Data)
		}()
	}
}

func checkVersion(data []byte) error {
	if len(data) < 6 {
		return errors.New("invalid SNMP packet")
	}
	if data[5] != 3 {
		return errors.New("this SNMP version is not implemented")
	}
	return nil
}
