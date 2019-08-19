GO ?= go

all: blobber sepdir

blobber:
	$(GO) build $(GOFLAGS) -o $@/$@ $@/*.go

sepdir:
	$(GO) build $(GOFLAGS) -o $@/$@ $@/*.go

.PHONY: all blobber sepdir
