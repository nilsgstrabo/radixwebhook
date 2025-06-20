FROM --platform=$BUILDPLATFORM docker.io/golang:1.24-alpine3.22 AS builder
ARG TARGETARCH
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=${TARGETARCH}

WORKDIR /src

COPY ./go.mod ./go.sum ./
RUN go mod download
COPY . .
RUN go build -ldflags="-s -w" -o /manager

# Final stage, ref https://github.com/GoogleContainerTools/distroless/blob/main/base/README.md for distroless
FROM gcr.io/distroless/static

COPY --from=builder /manager .

ENTRYPOINT ["/manager"]