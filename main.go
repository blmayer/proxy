package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strings"

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

type domain struct {
	Name string
	To string
	Cert tls.Certificate
}

// find certificate files
func loadDomains(root string) (map[string]domain, error) {
	dir, err := os.Open(root)
	if err != nil {
		return nil, err
	}
	domains, err := dir.Readdirnames(0)
	if err != nil {
		return nil, err
	}

	certMap := map[string]domain{}
	for _, dom := range domains {
		p := path.Join(root, dom)

		cert, err := tls.LoadX509KeyPair(p+"/fullchain.pem", p+"/privkey.pem")
		if err != nil {
			return nil, err
		}

		// get forward address
		toBytes, err := os.ReadFile(p+"/addr")
		if err != nil {
			print.Error("error reading addr for", dom)
			continue
		}

		certMap[dom] = domain{
			Name: dom, 
			To: strings.TrimSpace(string(toBytes)),
			Cert: cert,
		}
		print.Info("added", dom, "->", certMap[dom].To)
	}
	return certMap, nil
}

func main() {
	print.SetPrefix("proxy")

	port := "443"
	root := "/certs"
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-h", "--help":
			println(help)
			os.Exit(0)
		case "-p", "--port":
			i++
			port = os.Args[i]
		case "-r", "--root":
			i++
			root = os.Args[i]
		default:
			println("error: wrong argument", os.Args[i], "\n", help)
			os.Exit(-1)
		}
	}
	certMap, err := loadDomains(root)
	if err != nil {
		panic(err)
	}

	cfg := &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			dom, ok := certMap[info.ServerName]
			if !ok {
				return nil, fmt.Errorf("certificate for %s not found", info.ServerName)
			}
			return &dom.Cert, nil
		},
	}
	tcp, err := net.Listen("tcp", ":"+port)
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
		listener := tls.Server(conn, cfg)
		err = listener.Handshake()
		if err != nil {
			print.Error("handshake error:", err.Error())
			conn.Close()
			continue
		}
		name := listener.ConnectionState().ServerName
		print.Info("got request to %+v\n", name)
		dom := certMap[name]

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
