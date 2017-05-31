Minimal version for [github.com/zmap/zgrab](https://github.com/zmap/zgrab).

### Build

```bash
$ go get
$ go build zgrab-mini.go

$ ./zgrab-mini.go -h
Usage of ./zgrab-mini:
  -data-file string
    	Send data to grab banner when empty captured
  -ignore-meta-log
    	Ignore metadata log
  -input-file string
    	Input filename, use - for stdin (default "-")
  -output-file string
    	Output filename, use - for stdout (default "-")
  -read-max-length uint
    	Max read length of banner (default 65535)
  -save-error
    	If save error exception
  -save-tls
    	If save TLS certs
  -senders uint
    	Numbers of send coroutines to use (default 500)
  -timeout uint
    	Set connection timeout in seconds (default 10)
```

### With Zmap

```bash
# zmap -p 80 | awk '{print $1":80"}' | ./zgrab-mini
```

### With Masscan

```bash
# masscan -p80,443 --excludefile=blacklist.conf 0.0.0.0/0 | awk -F '/' '{print $1" "$2}' | awk '{print $7":"$4}' | ./zgrab-mini
```

### TODO

- [x] Protocol Data Definition Support
- [ ] Protocol Data Rules File Support
