FROM golang:1.23.0 
RUN apt-get update && apt-get install -y \
clang \
llvm \
make \ 
gcc \ 
linux-headers-generic \
iproute2 \
bpftool \
&& rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN make docker
RUN chmod +x main 
CMD ["./main"]