package helper

import (
	"io/ioutil"

	"git.sr.ht/~rumpelsepp/rlog"
)

var Logger = rlog.NewLogger(ioutil.Discard)

func init() {
	Logger.SetModule("[sep-helper]")
}
