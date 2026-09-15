.PHONY: build clean vet

build:
	mkdir -p build/
	go build -o build/inkmaild ./cmd/inkmaild/
	go build -o build/inkmail ./cmd/inkmail/

vet:
	go vet ./...

clean:
	rm -rf build/
