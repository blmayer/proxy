package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"blmayer.dev/x/print"
)

const help = `proxy: A simple proxy to remove TLS at one end
Usage:
proxy [options]
Available options:
  -h
  --help		show this help
  -p
  --port port	uses port as receive port, default 443
  -r
  --root path   uses path as the root of certificates, default certs/
  
Examples:
  proxy --help	show this help
  proxy -r files/cert	listen on port 1965 using ./files/cert as certificate
`

type Config struct {
	Port    string
	Domains []struct {
		Domain     string
		ToPort     string
		FullChain  string
		PrivateKey string
	}
}

type domain struct {
	Name string
	To   string
	Cert tls.Certificate
}

func main() {
	print.SetPrefix("proxy")

	file := "~/.config/proxy/config.json"
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-h", "--help":
			println(help)
			os.Exit(0)
		case "-c", "--config":
			i++
			file = os.Args[i]
		default:
			println("error: wrong argument", os.Args[i], "\n", help)
			os.Exit(-1)
		}
	}

	cfgFile, err := os.Open(file)
	if err != nil {
		panic(err)
	}
	defer cfgFile.Close()

	var cfg Config
	err = json.NewDecoder(cfgFile).Decode(&cfg)
	if err != nil {
		panic(err)
	}

	// default port
	if cfg.Port == "" {
		cfg.Port = "443"
	}

	certs := map[string]domain{}
	for _, dom := range cfg.Domains {
		cert, err := tls.LoadX509KeyPair(dom.FullChain, dom.PrivateKey)
		if err != nil {
			panic(err)
		}

		certs[dom.Domain] = domain{
			Name: dom.Domain,
			To:   dom.ToPort,
			Cert: cert,
		}
		print.Info("added", dom.Domain, "->", dom.ToPort)
	}
	
	tlsCfg := &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			dom, ok := certs[info.ServerName]
			if !ok {
				return nil, fmt.Errorf("certificate for %s not found", info.ServerName)
			}
			return &dom.Cert, nil
		},
	}

	tcp, err := net.Listen("tcp", ":"+cfg.Port)
	if err != nil {
		panic(err)
	}
	defer tcp.Close()

	for {
		conn, err := tcp.Accept()
		if err != nil {
			print.Error("accept error:", err.Error())
			continue
		}
		print.Info("got a connection")

		// select certificate
		listener := tls.Server(conn, tlsCfg)
		err = listener.Handshake()
		if err != nil {
			print.Error("handshake error:", err.Error())
			conn.Close()
			continue
		}
		name := listener.ConnectionState().ServerName
		print.Info("got request to " + name)
		dom := certs[name]

		go func(c net.Conn) {
			// echo all incoming data to the requested host
			cli, err := net.Dial("tcp", dom.To)
			if err != nil {
				print.Error(name, "dial error:", err.Error())
				c.Close()
				return
			}

			go func() {
				if _, err = io.Copy(c, cli); err != nil && !errors.Is(err, net.ErrClosed) {
					print.Error(name, "copy c cli error:", err.Error())
				}
				c.Close()
			}()

			print.Info("forwarding to", name, "on", dom.To)
			if _, err := io.Copy(cli, c); err != nil && !errors.Is(err, net.ErrClosed) {
				print.Error(name, "copy cli c error:", err.Error())
			}
			cli.Close()
		}(listener)
	}
}
