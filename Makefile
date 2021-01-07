# Makefile for building

# Project binaries
COMMANDS=lunfqueue
BINARIES=$(addprefix bin/,$(COMMANDS))

# Used to populate version in binaries
VERSION=$(shell git describe --match 'v[0-9]*' --dirty='.m' --always | sed 's/^v//')
REVISION=$(shell git rev-parse HEAD)$(shell if ! git diff --no-ext-diff --quiet --exit-code; then echo .m; fi)
DATEBUILD=$(shell date +%FT%T%z)

# Compilation opts
GOPATH?=$(HOME)/go
SYSTEM:=
CGO_ENABLED:=0
BUILDOPTS:=-v
BUILDLDFLAGS=-ldflags '-s -w -X main.Version=$(VERSION) -X main.Revision=$(REVISION) -X main.Build=$(DATEBUILD) $(EXTRA_LDFLAGS)'

# Print output
WHALE = "+"


.PHONY: all binaries clean
all: binaries

FORCE:

bin/%: cmd/% FORCE
	@echo "$(WHALE) $@${BINARY_SUFFIX}"
	GO111MODULE=on CGO_ENABLED=0 $(SYSTEM) \
		go build $(BUILDOPTS) -o $@${BINARY_SUFFIX} ${BUILDLDFLAGS} ./$< 

binaries: $(BINARIES)
	@echo "$(WHALE) $@"


clean:
	@echo "$(WHALE) $@"
	@rm -f $(BINARIES)
	@rmdir bin

## Targets for Makefile.release
.PHONY: release
release:
	@$(if $(value BINARY),, $(error Undefined BINARY))
	@$(if $(value COMMAND),, $(error Undefined COMMAND))
	@echo "$(WHALE) $@"
	GO111MODULE=on CGO_ENABLED=$(CGO_ENABLED) $(SYSTEM) \
		go build $(BUILDOPTS) ${BUILDLDFLAGS} -o $(BINARY) ./cmd/$(COMMAND)

.PHONY: test
test: 
	@echo "$(WHALE) $@"
