.PHONY: build test clean lint run-ingest run-correlate run-query

BINDIR := bin
MODULE := github.com/SentinelSIEM/sentinel-siem

all: build

build:
	-@if not exist $(BINDIR) mkdir $(BINDIR)
	go build -o $(BINDIR)/sentinel-ingest.exe ./cmd/sentinel-ingest
	go build -o $(BINDIR)/sentinel-correlate.exe ./cmd/sentinel-correlate
	go build -o $(BINDIR)/sentinel-query.exe ./cmd/sentinel-query
	go build -o $(BINDIR)/sentinel-cli.exe ./cmd/sentinel-cli
	@echo All binaries built in $(BINDIR)/

test:
	go test ./...

lint:
	go vet ./...

clean:
	-@if exist $(BINDIR) rmdir /s /q $(BINDIR)

run-ingest: build
	$(BINDIR)/sentinel-ingest.exe

run-correlate: build
	$(BINDIR)/sentinel-correlate.exe

run-query: build
	$(BINDIR)/sentinel-query.exe
