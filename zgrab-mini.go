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

    "io/ioutil"
    "encoding/json"

    "github.com/zmap/zcrypto/tls"
)

type Config struct {
    Senders uint
    Timeout time.Duration
    Data    []byte
}

type Summary struct {
    Success   uint           `json:"success_count"`
    Failure   uint           `json:"failure_count"`
    Total     uint           `json:"total"`
    Senders   uint           `json:"senders"`
    Timeout   uint           `json:"timeout"`
    StartTime int32          `json:"start_time"`
    EndTime   int32          `json:"end_time"`
    Cost      int32          `json:"cost"`
}

var (
    config Config
)

var (
    outputFileName string
    inputFileName  string
    inputFile      *os.File
    outputFile     *os.File
    timeout        uint
    summary        Summary
    maxReadLength  uint
    saveTLS        bool
    saveError      bool
    dataFileName   string
    ignoreMetaLog  bool
    dataFile       *os.File
    customData     bool
)

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
    BannerBytes  []byte                `json:"banner_bytes"`
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
        if customData {
            data, err = GrabBannerData(c, &t)
        } else {
            data, err = GrabBannerHTTPS(c, &t)
        }
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
    data.BannerBytes = buff[:n]
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
    data.BannerBytes = buff[:n]
    data.Banner = string(buff[:n])
    data.Component = "http"
    return data, err
}

// TODO: 解决 HTTPS 读取 Banner 时，无法获取完全的 BUG（通常获取到 Headers 就返回了）
func GrabBannerHTTPS(c *Config, t *GrabTarget) (data GrabData, err error) {
    address := t.GetAddress()
    dialer := MakeDialer(c)

    conf := tls.Config{
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

    if !saveTLS {
        data.TLSHandshake = nil
    } else {
        data.TLSHandshake = tlsConn.GetHandshakeLog()
    }
    data.IsTLS = true

    data.BannerBytes = buff[:n]
    data.Banner = string(buff[:n])
    data.Component = "https"
    return data, err
}

func GrabBannerData(c *Config, t *GrabTarget) (data GrabData, err error) {
    address := t.GetAddress()
    dialer := MakeDialer(c)

    conn, err := dialer.Dial("tcp", address)
    if err != nil {
        return data, err
    }
    defer conn.Close()

    conn.SetWriteDeadline(time.Now().Add(c.Timeout))
    _, err = conn.Write(c.Data)
    if err != nil {
        return data, err
    }

    conn.SetReadDeadline(time.Now().Add(c.Timeout))
    buff := make([]byte, maxReadLength)
    n, err := conn.Read(buff)
    if err != nil {
        return data, err
    }
    data.BannerBytes = buff[:n]
    data.Banner = string(buff[:n])
    data.Component = "data"
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

    flag.BoolVar(&saveError, "save-error", false, "If save error exception")
    flag.BoolVar(&saveTLS, "save-tls", false, "If save TLS certs")

    flag.BoolVar(&ignoreMetaLog, "ignore-meta-log", false, "Ignore metadata log")

    flag.StringVar(&dataFileName, "data-file", "", "Send data to grab banner when empty captured")

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

    if dataFileName != "" {
        if dataFile, err = os.Open(dataFileName); err != nil {
            log.Fatal(err)
        }
        buff, _ := ioutil.ReadAll(dataFile)
        config.Data = buff
        customData = true
    } else {
        customData = false
    }
}

/*
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
                if !saveError {
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

    go func() {
        if !ignoreMetaLog {
            speed := int32(0)
            time.Sleep(time.Duration(1) * time.Second)
            for {
                speed = int32(summary.Total) / (int32(time.Now().Unix()) - summary.StartTime)
                log.Printf("[MetaLog] total: %d, success: %d, failure: %d (%d/s)", summary.Total,
                    summary.Success, summary.Failure, speed)
                time.Sleep(time.Duration(2) * time.Second)
            }
        } else {
            return
        }
    }()

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
    summary.Cost = summary.EndTime - summary.StartTime
    summaryJSON, err := json.Marshal(summary)
    if err != nil {
        panic(err)
    }
    fmt.Println(string(summaryJSON))
}
