FROM gcc:latest

# Remove existing ping utilities installed by default
RUN apt-get update && apt-get remove -y iputils-ping && apt-get autoremove -y

# Install required dependencies
RUN apt-get install -y --no-install-recommends \
    texinfo \
    libreadline-dev \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Download and install inetutils-2.0
WORKDIR /tmp
RUN wget https://ftp.gnu.org/gnu/inetutils/inetutils-2.0.tar.gz \
    && tar xzf inetutils-2.0.tar.gz \
    && cd inetutils-2.0 \
    && ./configure \
    && make \
    && make install

CMD ["bash"]
