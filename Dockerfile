# Start from the latest Ubuntu image
FROM ubuntu:latest

# Install dependencies
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libelf-dev \
    zlib1g-dev \
    gcc \
    build-essential \
    pkgconf

# Copy your source code into the image
COPY . /src

# Set the working directory
WORKDIR /src

# Set up libbpf
RUN make -C lib/libbpf/src && make -C lib/libbpf/src install

# bpftool
RUN make -C lib/bpftool/src && make -C lib/bpftool/src install


# Compile the project
RUN make