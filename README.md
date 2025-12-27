# dproxy

Steps to compile:
```
git clone https://github.com/cbuijs/dproxy.git
cd dproxy
go mod tidy
go build -v -x -o dproxy main.go
chmod +x dproxy
./dproxy -h
```

