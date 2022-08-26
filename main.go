package main

import (
	"fmt"
	"io"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"path"
	"strings"
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
  --root path   uses path as the root of files, default static/
  
Examples:
  proxy --help	show this help
  proxy -c files/cert	listen on port 1965 using ./files/cert as certificate
`

type domain struct {
	Name string
	PortMap map[string]string
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
		println("found domain", dom)

		// load certs
		cert, err := tls.LoadX509KeyPair(p+"/fullchain.pem", p+"/privkey.pem")
		if err != nil {
			return nil, err
		}

		// get port
		portBytes, err := os.ReadFile(p+"/ports")
		if err != nil {
			return nil, err
		}

		portMap := map[string]string{}
		for _, line := range strings.Fields(string(portBytes)) {
			ps := strings.Split(line, ":")
			portMap[ps[0]] = ps[1]
			println("added port rule", ps[0], "->", ps[1])
		}

		certMap[dom] = domain{
			Name: dom, 
			PortMap: portMap,
			Cert: cert,
		}
	}
	return certMap, nil
}

func main() {
	port := "443"
	root := "static/"

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
			println(err)
		}

		// select certificate
		listener := tls.Server(conn, cfg)
		err = listener.Handshake()
		if err != nil {
			println(err.Error())
			conn.Close()
			continue
		}
		name := listener.ConnectionState().ServerName
		fmt.Printf("got request to %+v\n", name)
		dom := certMap[name]

		go func(c net.Conn) {
			// echo all incoming data to the requested host
			cli, err := net.Dial("tcp", ":"+dom.PortMap[port])
			if err != nil {
				println(err.Error())
				c.Close()
				return
			}
			
			go func() {
				if _, err = io.Copy(c, cli); err != nil && !errors.Is(err, net.ErrClosed) {
					println("copy c cli error:", err.Error())
				}
				c.Close()
			}()
			if _, err := io.Copy(cli, c); err != nil && !errors.Is(err, net.ErrClosed) {
				println("copy cli c error:", err.Error())
			}
			cli.Close()
			println("connected to", name, "on port", dom.PortMap[port])
		}(listener)
	}
}

