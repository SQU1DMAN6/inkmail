build:
	mkdir -p build/
	go build -o build/inkmaild ./cmd/inkmaild/
	go build -o build/inkmail ./cmd/inkmail/

clean:
	rm -rf build/

daemon:
	go run ./cmd/inkmaild

client:
	go run ./cmd/inkmail
