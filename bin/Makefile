GO ?= go

all: blobber delegator delegfetch directory keygen relay sepdir

blobber:
	$(GO) build $(GOFLAGS) -o $@/$@ $@/*.go

delegator:
	$(GO) build $(GOFLAGS) -o $@/$@ $@/*.go

delegfetch:
	$(GO) build $(GOFLAGS) -o $@/$@ $@/*.go

directory:
	$(GO) build $(GOFLAGS) -o $@/$@ $@/*.go

keygen:
	$(GO) build $(GOFLAGS) -o $@/$@ $@/*.go

relay:
	$(GO) build $(GOFLAGS) -o $@/$@ $@/*.go

sepdir:
	$(GO) build $(GOFLAGS) -o $@/$@ $@/*.go

.PHONY: all blobber delegator delegfetch directory keygen relay sepdir
