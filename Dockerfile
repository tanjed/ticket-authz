FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /authz ./cmd/authz

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /authz /authz
EXPOSE 8080 8081
# Applies the migrations, then serves.
ENTRYPOINT ["/authz"]
