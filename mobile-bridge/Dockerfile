# Build
FROM golang:1.26.3-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /mobile-bridge .

# Run
FROM gcr.io/distroless/static-debian12
COPY --from=build /mobile-bridge /mobile-bridge
EXPOSE 8066
USER nonroot:nonroot
ENTRYPOINT ["/mobile-bridge"]
