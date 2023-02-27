check_dependencies:
ifeq (, $(shell command -v npm))
	$(error "npm is required and is not installed")
else ifeq (, $(shell command -v go))
	$(error "go is required and is not installed")
else ifeq (, $(shell command -v circom))
	$(error "circom is required and is not installed")
else ifeq (, $(shell command -v sha256sum))
	$(error "Coreutils is required and is not installed")
endif

install: check_dependencies
	go mod tidy
	cd circuit && npm install

compile:
	@cd ./circuit && sh circuit-compiler.sh census.circom

test:
ifeq (, $(wildcard ./artifacts/))
	$(error "run 'make compile' command first")
else
	@go test -v ./...
endif

artifacts:
	@cd ./circuit && sh gen-dev-artifacts.sh census.circom

all: check_dependencies install compile test