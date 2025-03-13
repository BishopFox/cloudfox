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
	sha1sum ./cloudfox/cloudfox.exe > ./cloudfox/sha1sum.txt
	zip ./cloudfox/cloudfox-windows-amd64.zip ./cloudfox/cloudfox.exe ./cloudfox/sha1sum.txt
	rm -rf ./cloudfox/cloudfox.exe ./cloudfox/sha1sum.txt

	GOOS=linux GOARCH=amd64 go build -o ./cloudfox/cloudfox .
	sha1sum ./cloudfox/cloudfox > ./cloudfox/sha1sum.txt
	zip ./cloudfox/cloudfox-linux-amd64.zip ./cloudfox/cloudfox ./cloudfox/sha1sum.txt
	rm -rf ./cloudfox/cloudfox ./cloudfox/sha1sum.txt

	GOOS=linux GOARCH=386 go build -o ./cloudfox/cloudfox .
	sha1sum ./cloudfox/cloudfox > ./cloudfox/sha1sum.txt
	zip ./cloudfox/cloudfox-linux-386.zip ./cloudfox/cloudfox ./cloudfox/sha1sum.txt
	rm -rf ./cloudfox/cloudfox ./cloudfox/sha1sum.txt

	GOOS=darwin GOARCH=amd64 go build -o ./cloudfox/cloudfox .
	sha1sum ./cloudfox/cloudfox > ./cloudfox/sha1sum.txt
	zip ./cloudfox/cloudfox-macos-amd64.zip ./cloudfox/cloudfox ./cloudfox/sha1sum.txt
	rm -rf ./cloudfox/cloudfox ./cloudfox/sha1sum.txt

	GOOS=darwin GOARCH=arm64 go build -o ./cloudfox/cloudfox .
	sha1sum ./cloudfox/cloudfox > ./cloudfox/sha1sum.txt
	zip ./cloudfox/cloudfox-macos-arm64.zip ./cloudfox/cloudfox ./cloudfox/sha1sum.txt
	rm -rf ./cloudfox/cloudfox ./cloudfox/sha1sum.txt

clean:
	rm -rf ./cloudfox
