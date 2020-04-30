package snmp3

import (
	"log"
	"os"
	"sync"
)

type Logger interface {
	Println(...interface{})
}

var logger Logger = log.New(os.Stderr, "", log.LstdFlags)
var logMu sync.Mutex

func SetLogger(l Logger) {
	if l == nil {
		l = log.New(os.Stderr, "", log.LstdFlags)
	}

	logMu.Lock()
	logger = l
	logMu.Unlock()
}
