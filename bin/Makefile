GO ?= go

all: blobber delegator delegfetch directory keygen relay sepdir

blobber:
	$(GO) build $(GOFLAGS) -o $@/$@ ./$@/...

delegator:
	$(GO) build $(GOFLAGS) -o $@/$@ ./$@/...

delegfetch:
	$(GO) build $(GOFLAGS) -o $@/$@ ./$@/...

directory:
	$(GO) build $(GOFLAGS) -o $@/$@ ./$@/...

keygen:
	$(GO) build $(GOFLAGS) -o $@/$@ ./$@/...

relay:
	$(GO) build $(GOFLAGS) -o $@/$@ ./$@/...

sepdir:
	$(GO) build $(GOFLAGS) -o $@/$@ ./$@/...

.PHONY: all blobber delegator delegfetch directory keygen relay sepdir
