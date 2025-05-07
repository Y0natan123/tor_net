FROM ubuntu:22.04
RUN apt-get update && apt-get install -y \
    build-essential \
    iputils-ping \
    libsqlite3-dev
COPY . .
RUN g++ -o main *.cpp -pthread -lsqlite3
CMD ["./main", "172.21.112.1"]