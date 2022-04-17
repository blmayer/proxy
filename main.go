package main

import (
	"fmt"
	"io"
	"crypto/tls"
	"net"
	"os"
	"path"
)


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
	certMap, err := loadCerts("/certs")
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
	tcp, err := net.Listen("tcp", ":2000")
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
			cli, err := net.Dial("tcp", connInfo.ServerName+":80")
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

