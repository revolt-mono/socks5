FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /socks5 ./cmd/socks5

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /socks5 /socks5
EXPOSE 5000/tcp
ENTRYPOINT ["/socks5"]
