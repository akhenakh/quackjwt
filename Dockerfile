# Local test image — build with:  docker build -t oauth-server .
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o /out/oauth-server ./cmd/oauth-server

FROM gcr.io/distroless/cc-debian13
COPY --from=build /out/oauth-server /ko-app/oauth-server
ENTRYPOINT ["/ko-app/oauth-server"]
