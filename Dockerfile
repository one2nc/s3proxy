FROM golang:alpine AS builder
# Install git.
# Git is required for fetching the dependencies.
RUN apk update && apk add --no-cache git

COPY . $GOPATH/src/tsocial/s3proxy/
WORKDIR $GOPATH/src/tsocial/s3proxy/
# Fetch dependencies.
# Using go get.
RUN go get -d -v .
# Build the binary.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -ldflags="-w -s" -o /go/bin/s3proxy

FROM alpine
RUN apk add --no-cache ca-certificates
# Copy our static executable.
COPY --from=builder /go/bin/s3proxy .
