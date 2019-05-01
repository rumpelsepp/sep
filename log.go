package sep

import log "git.sr.ht/~rumpelsepp/logging"

var (
	announceLogger = log.NewLogger()
	dialLogger     = log.NewLogger()
	muxLogger      = log.NewLogger()
	tlsLogger      = log.NewLogger()
	relayLogger    = log.NewLogger()
	resolveLogger  = log.NewLogger()
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

	log.SetLogLevel(loglevel)
}
