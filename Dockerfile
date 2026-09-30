FROM ubuntu:24.04
RUN apt-get update && apt-get install -y build-essential git perl ca-certificates dnsutils
ARG REF=openssl-4.0.3
RUN git clone --depth 1 --branch "$REF" https://github.com/openssl/openssl.git /src \
 && cd /src && ./config --prefix=/opt/ssl --libdir=lib no-tests no-docs \
 && make -j$(nproc) && make install_sw
ENV PATH="/opt/ssl/bin:${PATH}" LD_LIBRARY_PATH="/opt/ssl/lib"
