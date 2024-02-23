FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y \
        g++ \
        cmake \
        libyara-dev \
        binutils \
        zlib1g-dev \
        libjansson-dev \
        git \
        openssh-client

# Crie o diretório SSH e coloque a chave SSH
RUN mkdir -p /root/.ssh && \
    echo "$SSH_PRIVATE_KEY" > /root/.ssh/id_ed25519 && \
    chmod 600 /root/.ssh/id_ed25519

COPY . /app
WORKDIR /app

COPY .git .git
COPY .gitmodules .gitmodules

# Inicialize e atualize os submódulos antes de continuar com o restante do processo de construção
RUN git submodule update --init --recursive

# Continue com o restante do processo de construção
RUN mkdir -p build && \
    cd build && \
    cmake .. && \
    make
