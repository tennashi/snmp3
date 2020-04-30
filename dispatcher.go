package snmp3

import (
	"context"
	"encoding/asn1"
	"errors"
	"net"
	"time"
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
	if d.MaxRecvSize == 0 {
		d.MaxRecvSize = defaultMaxRecvSize
	}

	var tempDelay time.Duration
	buf := make([]byte, d.MaxRecvSize)
	for {
		l, addr, err := c.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				}
				logger.Println("snmp: read error: %v; retrying in %v", err, tempDelay)
				exponentialWait(tempDelay, 1*time.Second)
				continue
			}
			logger.Println(err)
			return err
		}
		// Reset tempDelay
		tempDelay = 0
		data := make([]byte, l)
		copy(data, buf[:l])
		if err := checkVersion(data); err != nil {
			logger.Println(err)
			continue
		}
		go func() {
			p, err := d.mpm.PrepareDataElements(data)
			if err != nil {
				logger.Println(err)
				return
			}
			p.RemoteAddr = addr
			switch p.Data.typ {
			case PDUTypeSNMPV2Trap:
				d.notificationReceiver.ProcessPDU(context.Background(), p)
			}
		}()
	}
}

func exponentialWait(delay, max time.Duration) (next time.Duration) {
	if delay >= max {
		delay = max
	}
	time.Sleep(delay)
	return delay * 2
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
