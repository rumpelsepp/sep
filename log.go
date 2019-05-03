package sep

import "git.sr.ht/~rumpelsepp/rlog"

var (
	announceLogger = rlog.NewLogger()
	dialLogger     = rlog.NewLogger()
	muxLogger      = rlog.NewLogger()
	tlsLogger      = rlog.NewLogger()
	relayLogger    = rlog.NewLogger()
	resolveLogger  = rlog.NewLogger()
)

func InitLogging(loglevel int) {
	announceLogger.SetLogLevel(loglevel)
	announceLogger.SetModule("announce")

	dialLogger.SetLogLevel(loglevel)
	dialLogger.SetModule("dial")

	muxLogger.SetLogLevel(loglevel)
	muxLogger.SetModule("mux")

	tlsLogger.SetLogLevel(loglevel)
	tlsLogger.SetModule("tls")

	relayLogger.SetLogLevel(loglevel)
	relayLogger.SetModule("relay")

	resolveLogger.SetLogLevel(loglevel)
	resolveLogger.SetModule("resolve")

	rlog.SetLogLevel(loglevel)
}
