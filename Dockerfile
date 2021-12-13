FROM rust:1.57 as builder

WORKDIR /usr/src/bimi-agent
COPY . .
RUN cargo install --path .

FROM debian:bullseye-slim
EXPOSE 8000

ENV TZ=Etc/UTC \
    APP_USER=bimi

RUN apt-get update && apt-get install -y libssl1.1 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/bimi-agent /usr/local/bin/bimi-agent
COPY --from=builder /usr/src/bimi-agent/data/bimi_ca.pem /usr/local/share/bimi_ca.pem
RUN groupadd $APP_USER \
    && useradd -g $APP_USER $APP_USER
USER $APP_USER
CMD ["bimi-agent", "--ssl-ca-file", "/usr/local/share/bimi_ca.pem"]
