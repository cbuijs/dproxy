# dproxy

Steps to compile:
```
git clone https://github.com/cbuijs/dproxy.git
cd dproxy
go mod tidy
go build -v -x -ldflags="-s -w" -o dproxy
chmod +x dproxy
./dproxy -h
```

NOTE: Better documentation is in the making :-). Check the `config_example.yaml` file for more info.


==== LINUX PERFORMANCE TWEAKS ===

ulimit -n 65535

net.ipv4.ip_local_port_range = 1025 65535

net.core.rmem_default = 4194304
net.core.wmem_default = 4194304
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216

net.ipv4.udp_mem = 8388608 12582912 16777216

net.core.netdev_max_backlog = 10000

net.core.somaxconn = 65535

kernel.pid_max = 4194304

