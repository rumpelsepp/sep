module git.sr.ht/~rumpelsepp/sep/bin

go 1.14

require (
	git.sr.ht/~rumpelsepp/helpers v0.0.0-20191105065203-157bafb88180
	git.sr.ht/~rumpelsepp/ni v0.0.0-20190908142248-6f01ba11c9b7
	git.sr.ht/~rumpelsepp/rlog v0.0.0-20191119152513-6f7f3bf18e94
	git.sr.ht/~rumpelsepp/sep v0.0.0-00010101000000-000000000000
	git.sr.ht/~sircmpwn/getopt v0.0.0-20190808004552-daaf1274538b
	github.com/fxamacker/cbor v1.5.1
	github.com/fxamacker/cbor/v2 v2.2.0
	github.com/go-redis/redis/v7 v7.0.0-beta.4
	github.com/go-redis/redis/v8 v8.0.0-beta.7
	github.com/gorilla/mux v1.7.3
	github.com/kr/pretty v0.1.0 // indirect
	github.com/pelletier/go-toml v1.6.0
)

replace git.sr.ht/~rumpelsepp/sep => ../
