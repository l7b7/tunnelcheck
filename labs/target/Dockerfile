FROM golang:1.25-alpine AS build
WORKDIR /src
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /target main.go

FROM scratch
COPY --from=build /target /target
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/target"]
