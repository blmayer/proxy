package main

import (
	"fmt"
	"io"
	"crypto/tls"
	"net"
	"os"
	"path"
)

const help = `proxy: forward HTTPS to HTTP on your network
Usage:
  proxy [options]
Available options:
  -h
  --help		show this help
  -r
  --root path	uses path as the certificates root folder, default /certs
  -o
  --out port	uses port as the outgoing port, default 80
  -p
  --port port	uses port as receive port, default 443
Examples:
  proxy --help	show this help
  proxy -o 8080	listen on port 443 and forward to 8080
  proxy -r files/certificates	listen on port 443 and forward to 8080
				using ./files/certificates as certificate folder
`

// find certificate files
func loadCerts(root string) (map[string]tls.Certificate, error) {
	dir, err := os.Open(root)
	if err != nil {
		return nil, err
	}
	domains, err := dir.Readdirnames(0)
	if err != nil {
		return nil, err
	}

	certMap := map[string]tls.Certificate{}
	for _, dom := range domains {
		p := path.Join(root, dom)
		println("found domain", dom)

		// load certs
		certMap[dom], err = tls.LoadX509KeyPair(p+"/fullchain.pem", p+"/privkey.pem")
		if err != nil {
			return nil, err
		}
	}
	return certMap, nil
}

func main() {
	port := "443"
	outPort := "80"
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
		case "-o", "--out":
			i++
			outPort = os.Args[i]
		default:
			println("error: wrong argument", os.Args[i], "\n", help)
			os.Exit(-1)
		}
	}

	certMap, err := loadCerts(root)
	if err != nil {
		panic(err)
	}

	cfg := &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, ok := certMap[info.ServerName]
			if !ok {
				return nil, fmt.Errorf("certificate for %s not found", info.ServerName)
			}
			return &cert, nil
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
		connInfo := listener.ConnectionState()
		fmt.Printf("got request to %+v\n", connInfo.ServerName)

		go func(c net.Conn) {
			// echo all incoming data to the requested host
			cli, err := net.Dial("tcp", connInfo.ServerName+":"+outPort)
			if err != nil {
				println(err.Error())
				c.Close()
				return
			}
			
			go io.Copy(c, cli)
			go io.Copy(cli, c)
		}(listener)
	}
}

