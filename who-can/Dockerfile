FROM golang:1.13-buster as build

COPY who-can-runner/ /who-can-runner
WORKDIR /who-can-runner

RUN go build

FROM debian:buster-slim

COPY --from=build /who-can-runner/who-can-runner /who-can-runner
CMD ["bash", "-c", "/who-can-runner"]