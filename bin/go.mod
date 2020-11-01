module git.sr.ht/~rumpelsepp/sep/bin

go 1.14

require (
	git.sr.ht/~rumpelsepp/helpers v0.0.0-20201008105405-6d3088228e1a
	git.sr.ht/~rumpelsepp/ni v0.0.0-20190908142248-6f01ba11c9b7
	git.sr.ht/~rumpelsepp/rlog v0.0.0-20191119152513-6f7f3bf18e94
	git.sr.ht/~rumpelsepp/sep v0.0.0-20191204131725-54c6c07ca856
	git.sr.ht/~sircmpwn/getopt v0.0.0-20191230200459-23622cc906b3
	github.com/fxamacker/cbor/v2 v2.2.0
	github.com/go-redis/redis/v8 v8.3.3
	github.com/gorilla/mux v1.8.0
	github.com/pelletier/go-toml v1.8.1
)

replace git.sr.ht/~rumpelsepp/sep => ../
