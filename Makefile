all: test build

.PHONY: test build

test:
	go test -race -cover $$(go list -f '{{ .ImportPath }}' ./... | grep -v vendor)

build:
	go build
