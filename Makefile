build:
	mkdir -p build/
	go build -o build/inkmaild ./cmd/inkmaild/
	go build -o build/inkmail ./cmd/inkmail/

clean:
	rm -r build/
