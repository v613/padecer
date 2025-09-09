name=padecer

.PHONY: build build-optimized build-cross test clean

build:
	GOOS=windows GOARCH=amd64 go build -o $(name)-windows-amd64.exe .
	GOOS=linux GOARCH=amd64 go build -o $(name)-linux-amd64 .

build-optimized:
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o $(name)-windows-amd64.exe .
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(name)-linux-amd64 .

test:
	go test ./...

clean:
	rm -f $(name) $(name).exe