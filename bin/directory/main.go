package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"git.sr.ht/~rumpelsepp/helpers"
	"git.sr.ht/~rumpelsepp/ni"
	"git.sr.ht/~rumpelsepp/rlog"
	"git.sr.ht/~rumpelsepp/sep"
	"git.sr.ht/~sircmpwn/getopt"
	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
)

func parseCert(rawPEM string) (*x509.Certificate, error) {
	pemCert, err := url.QueryUnescape(rawPEM)
	if err != nil {
		return nil, fmt.Errorf("can't unescape cert: %w", err)
	}

	pemBlock, _ := pem.Decode([]byte(pemCert))
	if pemBlock == nil || pemBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("cannot decode PEM")
	}

	parsedCert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse cert: %w", err)
	}

	return parsedCert, nil
}

// Parsed datatype for convenience.
type announceReq struct {
	addresses []url.URL
	relays    []url.URL
	recordSet *sep.DirectoryRecordSet
}

func decodeRequest(r *http.Request) (*announceReq, error) {
	var (
		rs  sep.DirectoryRecordSet
		err error
	)

	parsedCert, err := parseCert(r.Header.Get("X-SSL-CERT"))
	if err != nil {
		return nil, err
	}

	remoteFp, err := sep.FingerprintFromPublicKey(parsedCert.PublicKey)
	if err != nil {
		return nil, err
	}

	if r.Method == http.MethodPut {
		err = helpers.RecvJSON(r, &rs)
		if err != nil {
			return nil, err
		}

		if ok, err := rs.CheckSignature(remoteFp); !ok || err != nil {
			return nil, fmt.Errorf("invalid signature")
		}
	}
	return &announceReq{recordSet: &rs}, nil
}

type apiServer struct {
	backends []backend
	expired  <-chan *sep.Fingerprint
	redis    *redis.Client
	zone     string
}

func (s *apiServer) getFingerprint(w http.ResponseWriter, r *http.Request) {
	req, err := decodeRequest(r)
	if err != nil {
		rlog.Warningf("decode error: %s", err)
		helpers.SendJSONError(w, fmt.Sprintf("decode error: %s", err), http.StatusBadRequest)
		return
	}

	fp, _ := req.recordSet.Fingerprint()

	answer := map[string]string{
		"ni":             fp.String(),
		"fqdn":           fp.FQDN(),
		"nih":            fp.NIH(),
		"well_known_uri": fp.WellKnownURI(),
	}

	helpers.SendJSON(w, answer)
}

func (s *apiServer) getDiscover(w http.ResponseWriter, r *http.Request) {
	var (
		resp  sep.DirectoryRecordSet
		vars  = mux.Vars(r)
		suite = vars["alg"]
		hash  = vars["val"]
	)

	rawNI := fmt.Sprintf("ni:///%s;%s", suite, hash)
	niURL, err := ni.ParseNI(rawNI)
	if err != nil {
		helpers.SendJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fp, err := sep.FingerprintFromRawNI(niURL)
	if err != nil {
		helpers.SendJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	key := fp.Canonical()

	vals, err := s.redis.LRange(context.Background(), key, 0, -1).Result()
	if err != nil {
		helpers.SendJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if len(vals) <= 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	for _, val := range vals {
		parts := strings.SplitN(val, "=", 2)

		switch parts[0] {
		case recordTypeAddress:
			resp.Addresses = append(resp.Addresses, parts[1])

		case recordTypeRelay:
			resp.Relays = append(resp.Relays, parts[1])

		case recordTypeBlob:
			resp.Blob, err = base64.StdEncoding.DecodeString(string(parts[1]))
			if err != nil {
				rlog.Warning(err)
				helpers.SendJSONError(w, err.Error(), http.StatusInternalServerError)
				return
			}

		case recordTypeSignature:
			resp.Signature, err = base64.StdEncoding.DecodeString(string(parts[1]))
			if err != nil {
				rlog.Warning(err)
				helpers.SendJSONError(w, err.Error(), http.StatusInternalServerError)
				return
			}

		case recordTypeTimestamp:
			err = resp.Timestamp.UnmarshalText([]byte(parts[1]))
			if err != nil {
				rlog.Warning(err)
				helpers.SendJSONError(w, err.Error(), http.StatusInternalServerError)
				return
			}

		case recordTypePubKey:
			resp.PubKey, err = base64.StdEncoding.DecodeString(parts[1])
			if err != nil {
				rlog.Warning(err)
				helpers.SendJSONError(w, err.Error(), http.StatusInternalServerError)
				return
			}

		case recordTypeTTL:
			if s, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
				resp.TTL = uint(s)
			} else {
				rlog.Warning(err)
				helpers.SendJSONError(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}

	helpers.SendJSON(w, resp)
}

func addRecordSet(b backend, rs *sep.DirectoryRecordSet) (int, error) {
	statusCode := http.StatusNoContent

	for {
		err := b.addRecordSet(rs)
		if err != nil {
			// If the recordSet exists, delete it and start again.
			if errors.Is(err, errRsExists) {
				// TODO: really able to discard the error?
				fp, _ := rs.Fingerprint()
				if err := b.rmRecordSet(fp); err != nil {
					return http.StatusInternalServerError, err
				}
				continue
			}
			return http.StatusInternalServerError, err
		}
		// TODO: check status codes according to spec.
		return statusCode, nil
	}
}

func (s *apiServer) putAnnounce(w http.ResponseWriter, r *http.Request) {
	req, err := decodeRequest(r)
	if err != nil {
		rlog.Warning(err)
		helpers.SendJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// TODO: Since all backends are supposed to be synchronized,
	// check if the statusCodes differ.
	statusCode := http.StatusNoContent
	for _, backend := range s.backends {
		statusCode, err = addRecordSet(backend, req.recordSet)
		if err != nil {
			rlog.Warning(err)
			break
		}
	}
	w.WriteHeader(statusCode)
}

func (s *apiServer) reapExpired() {
	for fp := range s.expired {
		for _, backend := range s.backends {
			if err := backend.rmRecordSet(fp); err != nil {
				rlog.Warning(err)
			}
		}
	}
}

func (s *apiServer) createHandler() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/", s.putAnnounce).Methods("PUT")
	r.HandleFunc("/.well-known/ni/{alg}/{val}", s.getDiscover).Methods("GET")
	r.HandleFunc("/fingerprint", s.getFingerprint).Methods("GET")
	return r
}

type runtimeOptions struct {
	bind      string
	bufsize   int
	redis     string
	zone      string
	dnsserver string
	ttl       int
	verbose   bool
	help      bool
}

func main() {
	opts := runtimeOptions{}
	getopt.StringVar(&opts.bind, "b", "127.0.0.1:8000", "Specify listening address")
	getopt.StringVar(&opts.redis, "r", "redis://localhost:6379/0", "Redis URL")
	getopt.StringVar(&opts.zone, "z", "ace-sep.de", "Specify managed DNS zone")
	getopt.StringVar(&opts.dnsserver, "d", "127.0.0.1", "DNS server to be managed")
	getopt.IntVar(&opts.ttl, "t", 60, "Create DNS records with this TTL")
	getopt.IntVar(&opts.bufsize, "s", 65536, "Set request queue size")
	getopt.BoolVar(&opts.verbose, "v", false, "Enable verbose logging")
	getopt.BoolVar(&opts.help, "h", false, "Show this page and exit")
	getopt.Parse()

	if opts.help {
		getopt.Usage()
		os.Exit(0)
	}

	if opts.verbose {
		rlog.SetLogLevel(rlog.DEBUG)
		sep.Logger.SetWriter(os.Stderr)
		rlog.SetLogLevel(rlog.DEBUG)
	}

	bindBackend, err := newNsupdateBackend(opts.dnsserver, opts.zone, opts.ttl)
	if err != nil {
		rlog.Critln(err)
	}

	redisOpts, err := redis.ParseURL(opts.redis)
	if err != nil {
		rlog.Critln(err)
	}

	// Allow setting the password via the environment. Overwrites anything
	// specified via URL.
	if passwd := os.Getenv("MARIA_REDIS_PASSWORD"); passwd != "" {
		redisOpts.Password = passwd
	}

	redisBackend, err := newRedisBackend(redisOpts)
	if err != nil {
		rlog.Critln(err)
	}

	expired, err := redisBackend.awaitExpireEvents()
	if err != nil {
		rlog.Critln(err)
	}

	apiSrv := apiServer{
		backends: []backend{redisBackend, bindBackend},
		redis:    redisBackend.client,
		expired:  expired,
	}

	go apiSrv.reapExpired()

	srv := &http.Server{
		Addr:         opts.bind,
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      apiSrv.createHandler(),
	}

	if err := srv.ListenAndServe(); err != nil {
		rlog.Critln(err)
	}
}
