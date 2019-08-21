GO ?= go

all: blobber delegfetch sepdir

blobber:
	$(GO) build $(GOFLAGS) -o $@/$@ $@/*.go

delegfetch:
	$(GO) build $(GOFLAGS) -o $@/$@ $@/*.go

sepdir:
	$(GO) build $(GOFLAGS) -o $@/$@ $@/*.go

.PHONY: all delegfetch blobber sepdir
