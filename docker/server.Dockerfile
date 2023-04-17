FROM rust:latest

RUN apt update && apt upgrade -y
RUN apt install -y protobuf-compiler libprotobuf-dev

WORKDIR app

COPY . .

RUN cargo build --release

CMD ./target/release/server
