package mbserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strings"
)

func (s *Server) accept(listen net.Listener) error {
	for {
		conn, err := listen.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return nil
			}

			log.Printf("Unable to accept connections: %#v\n", err)

			return err
		}

		go func(conn net.Conn) {
			defer conn.Close()

			var (
				user   string
				roleID = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 50316, 802, 1})
				role   []byte
			)

			if tlsConn, ok := conn.(*tls.Conn); ok {
				// Force TLS handshake so we can access peer certificate(s) before the
				// first read/write call on the connection.
				if err := tlsConn.Handshake(); err != nil {
					if err.Error() != "EOF" {
						log.Printf("TLS handshake error: %v", err)
					}

					return
				}

				certs := tlsConn.ConnectionState().PeerCertificates

				for _, cert := range certs {
					for _, ext := range cert.Extensions {
						if ext.Id.Equal(roleID) {
							user = cert.Subject.CommonName
							role = ext.Value
						}
					}
				}
			}

			for {
				packet := make([]byte, 512)

				n, err := conn.Read(packet)
				if err != nil {
					if err != io.EOF {
						log.Printf("read error %v\n", err)
					}

					return
				}

				// Set the length of the packet to the number of read bytes.
				packet = packet[:n]

				frame, err := NewTCPFrame(packet)
				if err != nil {
					log.Printf("bad packet error %v\n", err)
					return
				}

				ctx := context.Background()

				if host, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil {
					ctx = context.WithValue(ctx, "X-Forwarded-For", host)
				}

				if role != nil {
					ctx = context.WithValue(ctx, "Modbus-User", user)
					ctx = context.WithValue(ctx, "Modbus-Role", string(role))
				}

				request := &Request{ctx, conn, frame}

				s.requestChan <- request
			}
		}(conn)
	}
}

// ListenTCP starts the Modbus server listening on "address:port".
func (s *Server) ListenTCP(endpoint string) (err error) {
	listen, err := net.Listen("tcp", endpoint)
	if err != nil {
		log.Printf("Failed to Listen: %v\n", err)
		return err
	}

	s.listeners = append(s.listeners, listen)

	go s.accept(listen)

	return err
}

// ListenTLS starts the Modbus server listening securely on "address:port",
// using the key, certificate, and CA certificate at the paths provided.
func (s *Server) ListenTLS(endpoint, key, crt, ca string) error {
	config, err := createServerTLSConfig(ca, crt, key)
	if err != nil {
		return fmt.Errorf("creating TLS config: %w", err)
	}

	listen, err := tls.Listen("tcp", endpoint, config)
	if err != nil {
		return fmt.Errorf("listening for TLS on %s: %w", endpoint, err)
	}

	s.listeners = append(s.listeners, listen)

	go s.accept(listen)

	return err
}

func createServerTLSConfig(ca, crt, key string) (*tls.Config, error) {
	caCertPEM, err := ioutil.ReadFile(ca)
	if err != nil {
		return nil, fmt.Errorf("reading CA certificate: %w", err)
	}

	roots := x509.NewCertPool()

	if ok := roots.AppendCertsFromPEM(caCertPEM); !ok {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	cert, err := tls.LoadX509KeyPair(crt, key)
	if err != nil {
		return nil, fmt.Errorf("loading server certificate and key")
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    roots,
	}

	return config, nil
}
