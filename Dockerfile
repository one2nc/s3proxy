FROM alpine
RUN apk add --no-cache ca-certificates
# Copy our static executable.
COPY s3proxy .
