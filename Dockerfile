FROM ubuntu

RUN apt-get update
RUN apt-get install -y perl
RUN apt-get install -y make
RUN apt-get install -y curl
RUN apt-get install -y gcc
RUN apt-get install -y gocryptfs
RUN apt-get install -y kmod
RUN apt-get install -y module-assistant
RUN apt-get install -y fuse3
RUN apt install --reinstall linux-modules-$(uname -r) -y

RUN curl https://sh.rustup.rs -sSf | bash -s -- -y

RUN cargo build --release

CMD ["cargo", "run", "--release", "--"]
