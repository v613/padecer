#!/bin/bash
NAME=padecer
# LastTag=$(git tag -l --sort=-version:refname "v*" | head -n 1)
OS=("darwin" "linux" "windows")
ARCH=("amd64" "386")

for os in "${OS[@]}"
do
	echo "Building $os..."
	for arch in "${ARCH[@]}"
	do
		if [ "$arch" = "386" ] && [ "$os" = "darwin" ]; then
			continue
		fi
		
		echo "+$arch"
		ext=""
		if [ "$os" = "windows" ]; then
			ext=".exe"
		fi
		GOOS=$os GOARCH=$arch go build -o "$NAME-$os-$arch$ext"
	done
done