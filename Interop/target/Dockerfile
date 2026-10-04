FROM golang:1.25-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /target .

FROM scratch
COPY --from=build /target /target
ENTRYPOINT ["/target"]
