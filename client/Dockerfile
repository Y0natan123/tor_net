FROM mcr.microsoft.com/dotnet/runtime:9.0 AS runtime
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN ln -snf /usr/share/zoneinfo/Etc/UTC /etc/localtime && \
    echo "Etc/UTC" > /etc/timezone && \
    apt-get update && \
    apt-get install -y tzdata && \
    dpkg-reconfigure --frontend noninteractive tzdata
COPY --from=runtime /usr/share/dotnet /usr/share/dotnet
RUN ln -s /usr/share/dotnet/dotnet /usr/bin/dotnet
RUN apt-get update && apt-get install -y \
    build-essential \
    iputils-ping \
    libsqlite3-dev \
    libwxgtk3.0-gtk3-dev \
    libwxbase3.0-dev \
    wx-common \
    libwxgtk-media3.0-gtk3-0 \
    libwxgtk-media3.0-gtk3-dev \
    x11-common && rm -rf /var/lib/apt/lists/*
RUN apt-get update && apt-get install -y \
    libgl1-mesa-glx \
    libegl1 \
    libx11-xcb1 \
    libice6 \
    libsm6 \
    x11-common \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN g++ -fPIC -o main *.cpp \
    -pthread -lsqlite3 \
    `wx-config --cxxflags --libs` \
    `wx-config --cxxflags --libs media` \
    -I/usr/include/wx-3.0
ENV DISPLAY=:0
ENV DOTNET_ROOT=/usr/share/dotnet
CMD ["./main", "172.21.112.1", "172.21.112.2"]