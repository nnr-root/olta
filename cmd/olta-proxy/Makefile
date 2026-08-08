TARGET=olta-proxy
PACKAGES=../../pkg/proxy/core ../../pkg/proxy/database ../../pkg/proxy/log ../../pkg/proxy/parser

.PHONY: all build clean
all: build

build:
	@mkdir -p ./build
	@go build -o ./build/$(TARGET) .

clean:
	@go clean
	@rm -f ./build/$(TARGET)
