FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /garagat ./cmd/garagat

FROM scratch
COPY --from=build /garagat /garagat
ENTRYPOINT ["/garagat"]
