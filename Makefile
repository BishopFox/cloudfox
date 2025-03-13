run:
	go run main.go

windows:
	GOOS=windows GOARCH=386 go build 
	sha1sum cloudfox.exe > sha1sum-win.txt
	zip cloudfox-win.zip cloudfox.exe sha1sum-win.txt
	rm cloudfox.exe sha1sum-win.txt

linux:
	GOOS=linux GOARCH=386 go build
	sha1sum cloudfox > sha1sum-linux.txt
	zip cloudfox-linux.zip cloudfox sha1sum-linux.txt
	rm cloudfox sha1sum-linux.txt

linux-arm64:
	GOOS=linux GOARCH=arm64 go build
	sha1sum cloudfox > sha1sum-linux-arm64.txt
	zip cloudfox-linux-arm64.zip cloudfox sha1sum-linux-arm64.txt
	rm cloudfox sha1sum-linux-arm64.txt

macos:
	GOOS=darwin GOARCH=amd64 go build
	sha1sum cloudfox > sha1sum-mac.txt
	zip cloudfox-mac.zip cloudfox sha1sum-mac.txt
	rm cloudfox sha1sum-mac.txt

all: windows linux macos

.PHONY: release
release: clean
	mkdir -p ./cloudfox

	GOOS=windows GOARCH=amd64 go build -o ./cloudfox/cloudfox.exe .
	zip ./cloudfox/cloudfox-windows-amd64.zip ./cloudfox/cloudfox.exe
	rm -rf ./cloudfox/cloudfox.exe

	GOOS=linux GOARCH=amd64 go build -o ./cloudfox/cloudfox .
	zip ./cloudfox/cloudfox-linux-amd64.zip ./cloudfox/cloudfox .
	rm -rf ./cloudfox/cloudfox

	GOOS=linux GOARCH=386 go build -o ./cloudfox/cloudfox .
	zip ./cloudfox/cloudfox-linux-386.zip ./cloudfox/cloudfox .
	rm -rf ./cloudfox/cloudfox

	GOOS=linux GOARCH=arm64 go build -o ./cloudfox/cloudfox .
	zip ./cloudfox/cloudfox-linux-arm64.zip ./cloudfox/cloudfox .
	rm -rf ./cloudfox/cloudfox

	GOOS=darwin GOARCH=amd64 go build -o ./cloudfox/cloudfox .
	zip ./cloudfox/cloudfox-macos-amd64.zip ./cloudfox/cloudfox
	rm -rf ./cloudfox/cloudfox

	GOOS=darwin GOARCH=arm64 go build -o ./cloudfox/cloudfox .
	zip ./cloudfox/cloudfox-macos-arm64.zip ./cloudfox/cloudfox
	rm -rf ./cloudfox/cloudfox

clean:
	rm -rf ./cloudfox
