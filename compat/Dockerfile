# Image with caracal, garagat, tcpdump and the comparison tool.
# Build caracal first: docker build -t caracal-local <caracal checkout>
# Then from the garagat root: docker build -f compat/Dockerfile -t garagat-compat .
FROM golang:1.26 AS build
WORKDIR /garagat
COPY . .
RUN CGO_ENABLED=0 go build -o /out/garagat ./cmd/garagat && \
    CGO_ENABLED=0 go build -o /out/compare ./compat

FROM caracal-local
RUN apt-get update -qq && apt-get install -y -qq tcpdump iproute2 >/dev/null && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/garagat /usr/local/bin/garagat
COPY --from=build /out/compare /work/compare
COPY compat/run.sh /work/run.sh
ENTRYPOINT ["/work/run.sh"]
