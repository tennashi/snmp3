package snmp3

import (
	"bytes"
	"context"
	"errors"
	"net"
)

type EngineID []byte

func NewEngineID(d []byte) (EngineID, error) {
	if len(d) < 5 || len(d) > 32 {
		return nil, errors.New("invalid engine ID")
	}
	return EngineID(d), nil
}

func (e EngineID) Equal(o EngineID) bool {
	return bytes.Equal(e, o)
}

type Engine struct {
	d *Dispatcher
}

func NewEngine(lcd LocalConfigurationDatastore) *Engine {
	usm := NewUserSecurityModel(lcd)
	mpm := NewMessageProcessingModel(usm)
	d := NewDispatcher(mpm)

	return &Engine{d: d}
}

func (e *Engine) Serve(ctx context.Context, conn net.PacketConn) error {
	return e.d.Listen(ctx, conn)
}

type ErrorStatus int

const (
	ErrorStatusNoError ErrorStatus = iota
	ErrorStatusTooBig
	ErrorStatusNoSuchName
	ErrorStatusBadValue
	ErrorStatusReadOnly
	ErrorStatusGenErr
	ErrorStatusNoAccess
	ErrorStatusWrongType
	ErrorStatusWrongLength
	ErrorStatusWrongEncoding
	ErrorStatusWrongValue
	ErrorStatusNoCreation
	ErrorStatusInconsistentValue
	ErrorStatusResourceUnavailable
	ErrorStatusCommitFailed
	ErrorStatusUndoFailed
	ErrorStatusAuthorizationError
	ErrorStatusNotWritable
	ErrorStatusInconsistentName
)
