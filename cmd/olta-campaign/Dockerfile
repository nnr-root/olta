# Minify client side assets (JavaScript)
FROM node:latest AS build-js

RUN npm install gulp gulp-cli -g

WORKDIR /build
COPY cmd/olta-campaign/ .
RUN npm install --only=dev
RUN gulp


# Build Golang binary
FROM golang:1.22 AS build-golang

WORKDIR /go/src/github.com/s4l1hs/olta
COPY go.mod go.sum ./
RUN go mod download
COPY pkg/ ./pkg/
COPY cmd/olta-campaign/ ./cmd/olta-campaign/
RUN go build -v -o /out/olta-campaign ./cmd/olta-campaign


# Runtime container
FROM debian:stable-slim

RUN useradd -m -d /opt/olta-campaign -s /bin/bash app

RUN apt-get update && \
	apt-get install --no-install-recommends -y jq libcap2-bin && \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /opt/olta-campaign
COPY --from=build-golang /go/src/github.com/s4l1hs/olta/cmd/olta-campaign/ ./
COPY --from=build-golang /out/olta-campaign ./olta-campaign
COPY --from=build-js /build/static/js/dist/ ./static/js/dist/
COPY --from=build-js /build/static/css/dist/ ./static/css/dist/
RUN chown app. config.json

RUN setcap 'cap_net_bind_service=+ep' /opt/olta-campaign/olta-campaign

USER app
RUN sed -i 's/127.0.0.1/0.0.0.0/g' config.json
RUN touch config.json.tmp

EXPOSE 3333 8080 8443 80

CMD ["./docker/run.sh"]
