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

