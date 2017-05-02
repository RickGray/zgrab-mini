package main

import (
    "io"
    "os"
    "log"
    "fmt"
    "net"
    "time"
    "flag"
    "sync"
    "bufio"
    "strings"

    "encoding/json"
    //"crypto/x509"
    //"crypto/tls"
    //"github.com/zmap/zcrypto/x509"
    "github.com/zmap/zcrypto/tls"
)

//const rootPEM = `
//-----BEGIN CERTIFICATE-----
//MIIEBDCCAuygAwIBAgIDAjppMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT
//MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i
//YWwgQ0EwHhcNMTMwNDA1MTUxNTU1WhcNMTUwNDA0MTUxNTU1WjBJMQswCQYDVQQG
//EwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzElMCMGA1UEAxMcR29vZ2xlIEludGVy
//bmV0IEF1dGhvcml0eSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
//AJwqBHdc2FCROgajguDYUEi8iT/xGXAaiEZ+4I/F8YnOIe5a/mENtzJEiaB0C1NP
//VaTOgmKV7utZX8bhBYASxF6UP7xbSDj0U/ck5vuR6RXEz/RTDfRK/J9U3n2+oGtv
//h8DQUB8oMANA2ghzUWx//zo8pzcGjr1LEQTrfSTe5vn8MXH7lNVg8y5Kr0LSy+rE
//ahqyzFPdFUuLH8gZYR/Nnag+YyuENWllhMgZxUYi+FOVvuOAShDGKuy6lyARxzmZ
//EASg8GF6lSWMTlJ14rbtCMoU/M4iarNOz0YDl5cDfsCx3nuvRTPPuj5xt970JSXC
//DTWJnZ37DhF5iR43xa+OcmkCAwEAAaOB+zCB+DAfBgNVHSMEGDAWgBTAephojYn7
//qwVkDBF9qn1luMrMTjAdBgNVHQ4EFgQUSt0GFhu89mi1dvWBtrtiGrpagS8wEgYD
//VR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwOgYDVR0fBDMwMTAvoC2g
//K4YpaHR0cDovL2NybC5nZW90cnVzdC5jb20vY3Jscy9ndGdsb2JhbC5jcmwwPQYI
//KwYBBQUHAQEEMTAvMC0GCCsGAQUFBzABhiFodHRwOi8vZ3RnbG9iYWwtb2NzcC5n
//ZW90cnVzdC5jb20wFwYDVR0gBBAwDjAMBgorBgEEAdZ5AgUBMA0GCSqGSIb3DQEB
//BQUAA4IBAQA21waAESetKhSbOHezI6B1WLuxfoNCunLaHtiONgaX4PCVOzf9G0JY
///iLIa704XtE7JW4S615ndkZAkNoUyHgN7ZVm2o6Gb4ChulYylYbc3GrKBIxbf/a/
//zG+FA1jDaFETzf3I93k9mTXwVqO94FntT0QJo544evZG0R0SnU++0ED8Vf4GXjza
//HFa9llF7b1cq26KqltyMdMKVvvBulRP/F/A8rLIQjcxz++iPAsbw+zOzlTvjwsto
//WHPbqCRiOwY1nQ2pM714A5AuTHhdUDqB1O6gyHA43LL5Z/qHQF1hwFGPa4NrzQU6
//yuGnBXj8ytqU0CwIPX4WecigUCAkVDNx
//-----END CERTIFICATE-----`

type Config struct {
    Senders uint
    Timeout time.Duration
}

//type OutputConfig struct {
//    OutputFile *os.File
//}

type Summary struct {
    Success   uint           `json:"success_count"`
    Failure   uint           `json:"failure_count"`
    Total     uint           `json:"total"`
    Senders   uint           `json:"senders"`
    Timeout   uint           `json:"timeout"`
    StartTime int32          `json:"start_time"`
    EndTime   int32          `json:"end_time"`
}

var (
    config Config
    //outputConfig OutputConfig
)

var (
    outputFileName string
    inputFileName  string
    inputFile      *os.File
    outputFile     *os.File
    timeout        uint
    ignoreError    bool
    summary        Summary
    maxReadLength  uint
)

//type TLSHandshake struct {
//    State tls.ConnectionState   `json:"state"`
//}

type GrabTarget struct {
    IP   string   `json:"ip"`
    Port string   `json:"port"`
}

func (gt *GrabTarget) GetAddress() (string) {
    return gt.IP + ":" + gt.Port
}

type GrabResult struct {
    IP    string      `json:"ip"`
    Port  string      `json:"port"`
    Time  int32       `json:"timestamp"`
    Data  *GrabData   `json:"data,omitempty"`
    Error string      `json:"error,omitempty"`
}

type GrabData struct {
    Banner       string                `json:"banner"`
    IsTLS        bool                  `json:"is_tls"`
    TLSHandshake *tls.ServerHandshake  `json:"tls"`
    Component    string                `json:"component"`
}

type GrabWorker struct {
    InGrabTarget  chan GrabTarget
    OutGrabResult chan GrabResult
    c             *Config
}

func MakeDialer(c *Config) (net.Dialer) {
    return net.Dialer{
        Timeout: c.Timeout,
    }
}

func GrabBanner(c *Config, t GrabTarget) (GrabResult) {
    var err error
    var data GrabData

    result := GrabResult{
        IP:   t.IP,
        Port: t.Port,
    }
    data, err = GrabBannerBasic(c, &t)
    if err != nil {
        data, err = GrabBannerHTTPS(c, &t)
        if err != nil {
            data, err = GrabBannerHTTP(c, &t)
            if err != nil {
                result.Error = err.Error()
                result.Time = int32(time.Now().Unix())
                return result
            }
        }
    }
    result.Data = &data
    result.Time = int32(time.Now().Unix())
    return result
}

func GrabBannerBasic(c *Config, t *GrabTarget) (data GrabData, err error) {
    address := t.GetAddress()
    dialer := MakeDialer(c)

    conn, err := dialer.Dial("tcp", address)
    if err != nil {
        return data, err
    }
    defer conn.Close()

    conn.SetReadDeadline(time.Now().Add(c.Timeout))
    buff := make([]byte, maxReadLength)
    n, err := conn.Read(buff)
    if err != nil {
        return data, err
    }
    data.Banner = string(buff[:n])
    data.Component = "basic"
    return data, err
}

func GrabBannerHTTP(c *Config, t *GrabTarget) (data GrabData, err error) {
    address := t.GetAddress()
    dialer := MakeDialer(c)

    conn, err := dialer.Dial("tcp", address)
    if err != nil {
        return data, err
    }
    defer conn.Close()

    conn.SetWriteDeadline(time.Now().Add(c.Timeout))
    _, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + address + "\r\n\r\n"))
    if err != nil {
        return data, err
    }

    conn.SetReadDeadline(time.Now().Add(c.Timeout))
    buff := make([]byte, maxReadLength)
    n, err := conn.Read(buff)
    if err != nil {
        return data, err
    }
    data.Banner = string(buff[:n])
    data.Component = "http"
    return data, err
}

func GrabBannerHTTPS(c *Config, t *GrabTarget) (data GrabData, err error) {
    address := t.GetAddress()
    dialer := MakeDialer(c)

    //roots := x509.NewCertPool()
    //ok := roots.AppendCertsFromPEM([]byte(rootPEM))
    //if !ok {
    //    return data, err
    //}
    conf := tls.Config{
        //RootCAs:            roots,
        InsecureSkipVerify: true,
    }
    tlsConn, err := tls.DialWithDialer(&dialer, "tcp", address, &conf)
    if err != nil {
        return data, err
    }
    defer tlsConn.Close()

    tlsConn.SetWriteDeadline(time.Now().Add(c.Timeout))
    _, err = tlsConn.Write([]byte("GET / HTTP/1.1\r\nHost: " + address + "\r\n\r\n"))
    if err != nil {
        return data, err
    }

    tlsConn.SetReadDeadline(time.Now().Add(c.Timeout))
    buff := make([]byte, maxReadLength)
    n, err := tlsConn.Read(buff)
    if err != nil {
        return data, err
    }

    // TODO: parse TLS infomations
    //stateJSON, err := json.Marshal(tlsConn.ConnectionState())
    //if err != nil {
    //    fmt.Println(string(stateJSON))
    //}
    //data.TLSHandshake = xxxxx
    data.TLSHandshake = tlsConn.GetHandshakeLog()
    data.IsTLS = true

    data.Banner = string(buff[:n])
    data.Component = "https"
    return data, err
}

func (gw *GrabWorker) Start(wg *sync.WaitGroup) {
    go func() {
        for {
            target, ok := <-gw.InGrabTarget
            if !ok {
                break
            }
            result := GrabBanner(gw.c, target)
            gw.OutGrabResult <- result
        }
        wg.Done()
    }()
}

func init() {
    flag.StringVar(&inputFileName, "input-file", "-", "Input filename, use - for stdin")
    flag.StringVar(&outputFileName, "output-file", "-", "Output filename, use - for stdout")

    flag.UintVar(&config.Senders, "senders", 500, "Numbers of send coroutines to use")
    flag.UintVar(&timeout, "timeout", 10, "Set connection timeout in seconds")
    flag.UintVar(&maxReadLength, "read-max-length", 65535, "Max read length of banner")
    flag.BoolVar(&ignoreError, "ignore-error", false, "Ignore error output")

    flag.Parse()

    config.Timeout = time.Duration(timeout) * time.Second

    var err error

    switch inputFileName {
    case "-":
        inputFile = os.Stdin
    default:
        if inputFile, err = os.Open(inputFileName); err != nil {
            log.Fatal(err)
        }
    }

    switch outputFileName {
    case "-":
        outputFile = os.Stdout
    default:
        if outputFile, err = os.Create(outputFileName); err != nil {
            log.Fatal(err)
        }
    }
}

/*
Usage of ./zgrab-mini:
  -ignore-error
    	Ignore error output
  -input-file string
    	Input filename, use - for stdin (default "-")
  -output-file string
    	Output filename, use - for stdout (default "-")
  -read-max-length uint
    	Max read length of banner (default 65535)
  -senders uint
    	Numbers of send coroutines to use (default 500)
  -timeout uint
    	Set connection timeout in seconds (default 10)
 */
func main() {
    in := make(chan GrabTarget, config.Senders*5)
    out := make(chan GrabResult, config.Senders*5)

    defer inputFile.Close()
    defer outputFile.Close()

    wgWorker := sync.WaitGroup{}
    wgWorker.Add(int(config.Senders))

    summary.StartTime = int32(time.Now().Unix())
    for i := 0; i < int(config.Senders); i++ {
        worker := GrabWorker{in, out, &config}
        worker.Start(&wgWorker)
    }

    wgOutput := sync.WaitGroup{}
    wgOutput.Add(1)
    go func(wg *sync.WaitGroup) {
        for {
            result, ok := <-out
            if !ok {
                break
            }

            summary.Total += 1
            if result.Error != "" {
                summary.Failure += 1
                if ignoreError {
                    continue
                }
            } else {
                summary.Success += 1
            }

            encodeJSON, err := json.Marshal(result)
            if err != nil {
                continue
            }
            outputFile.WriteString(string(encodeJSON) + "\n")
        }
        wg.Done()
    }(&wgOutput)

    reader := bufio.NewReader(inputFile)
    for {
        line, err := reader.ReadString('\n')
        if err == io.EOF {
            break
        }
        line = strings.TrimSpace(line)
        if len(line) == 0 {
            continue
        } else {
            parts := strings.Split(line, ":")
            target := GrabTarget{
                IP:   parts[0],
                Port: parts[1],
            }
            in <- target
        }
    }
    close(in)
    wgWorker.Wait()
    close(out)
    wgOutput.Wait()

    summary.Timeout = timeout
    summary.Senders = config.Senders
    summary.EndTime = int32(time.Now().Unix())
    summaryJSON, err := json.Marshal(summary)
    if err != nil {
        panic(err)
    }
    fmt.Println(string(summaryJSON))
}
