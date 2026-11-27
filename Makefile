.PHONY: test build install site
test:
	go test ./...
	go vet ./...
build:
	go build -trimpath -o dist/tunnelcheck ./cmd/tunnelcheck
install:
	go install ./cmd/httpcheck ./cmd/tunnelcheck
site:
	python3 -m http.server 8000

