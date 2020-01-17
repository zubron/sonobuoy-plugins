FROM golang:1.13-buster as build

COPY runner/ /runner
WORKDIR /runner

RUN go build -o who-can-runner

RUN curl -L https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64 -o jq
RUN chmod +x jq

FROM debian:buster-slim

COPY --from=build /runner/who-can-runner /who-can-runner
COPY --from=build /runner/jq /jq
CMD ["bash", "-c", "/who-can-runner"]
