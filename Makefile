.PHONY: build test clean lint run-ingest run-correlate run-query install dev demo demo-clean dashboard

BINDIR := bin
MODULE := github.com/derekxmartin/akeso-siem

all: build

build:
	go build -o $(BINDIR)/akeso-ingest.exe ./cmd/akeso-ingest
	go build -o $(BINDIR)/akeso-correlate.exe ./cmd/akeso-correlate
	go build -o $(BINDIR)/akeso-query.exe ./cmd/akeso-query
	go build -o $(BINDIR)/akeso-cli.exe ./cmd/akeso-cli
	@echo All binaries built in $(BINDIR)/

test:
	go test ./...

lint:
	go vet ./...

clean:
	go clean
	-if exist $(BINDIR) rmdir /s /q $(BINDIR)
	@echo Cleaned build artifacts

# install: Full installation — build binaries, start Docker, apply ES templates,
# create admin user, print credentials and dashboard URL.
install:
	bash scripts/install.sh

# dev: Hot-reload development mode — starts Docker services, runs ingest + query
# servers, and starts the React dev server with live reload.
dev: build
	bash scripts/dev.sh

# demo: Full demo setup — install + create demo analyst accounts + replay all
# fixture datasets + trigger correlation rules + populate dashboard.
demo: build
	bash scripts/demo.sh

# demo-clean: Remove demo accounts, delete demo indices, stop services.
demo-clean:
	bash scripts/demo-clean.sh

# dashboard: Build the React dashboard for production.
dashboard:
	cd web && npm install && npm run build

run-ingest: build
	$(BINDIR)/akeso-ingest.exe

run-correlate: build
	$(BINDIR)/akeso-correlate.exe

run-query: build
	$(BINDIR)/akeso-query.exe
