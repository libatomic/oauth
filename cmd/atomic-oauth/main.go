package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/apex/log"
	"github.com/dgrijalva/jwt-go"
	"github.com/libatomic/api/pkg/api"
	"github.com/libatomic/oauth/api/server"
	"github.com/libatomic/oauth/pkg/oauth/rpc"
	"github.com/urfave/cli/v2"
	"google.golang.org/grpc"
)

var (
	// BuildVersion is the build version
	BuildVersion = "dev"
)

func main() {
	app := cli.NewApp()

	app.Name = "atomic-oauth"
	app.Usage = "Atomic Oauth 2.0 Server"
	app.Action = serverMain
	app.Version = BuildVersion

	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:    "rsa-private-key",
			EnvVars: []string{"RSA_PRIVATE_KEY"},
		},
		&cli.StringFlag{
			Name:    "rsa-pem-file",
			EnvVars: []string{"RSA_PEM_FILE"},
			Value:   ".oauth-rsa-key.pem",
		},
		&cli.StringFlag{
			Name:    "public-uri",
			EnvVars: []string{"PUBLIC_URI"},
			Value:   "http://localhost:9000",
		},
		&cli.StringFlag{
			Name:    "listen-addr",
			Aliases: []string{"l"},
			Value:   "0.0.0.0:9000",
			EnvVars: []string{"SERVER_LISTEN_ADDR"},
		},
		&cli.StringFlag{
			Name:    "controller-host",
			Aliases: []string{"l"},
			Value:   "http://0.0.0.0:9000/rpc",
			EnvVars: []string{"CONTROLLER_ADDR"},
		},
		&cli.StringFlag{
			Name:    "log-level",
			Usage:   "set the logging level",
			Value:   "info",
			EnvVars: []string{"LOG_LEVEL"},
		},
	}

	app.Before = func(c *cli.Context) error {
		if c.String("log-level") != "" {
			if level, err := log.ParseLevel(c.String("log-level")); err == nil {
				log.SetLevel(level)
			}
		}

		return nil
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err.Error())
	}
}

func serverMain(c *cli.Context) error {
	done := make(chan os.Signal, 1)

	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	key, err := getPrivateKey(c)
	if err != nil {
		return err
	}

	conn, err := grpc.Dial(c.String("controller-addr"))
	if err != nil {
		return err
	}

	// initialize the api server
	server := server.New(
		rpc.NewClient(conn),
		server.WithPrivateKey(key),
		api.WithLog(log.Log),
		api.WithAddr(c.String("listen-addr")),
	)

	go func() {
		if err := server.Serve(); err != nil {
			log.Fatalf("failed to start the oauth server %+v", err)
		}
	}()
	log.Infof("oauth server started")

	<-done
	log.Info("oauth server shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("shutdown:%+v", err)
	}
	log.Infof("oauth server shutdown")

	return nil
}

func getPrivateKey(c *cli.Context) (*rsa.PrivateKey, error) {
	// use the key from env
	if keyString := c.String("rsa-private-key"); keyString != "" {
		key, err := base64.StdEncoding.DecodeString(keyString)
		if err != nil {
			return nil, err
		}
		return jwt.ParseRSAPrivateKeyFromPEM(key)
	}

	fname := c.String("rsa-pem-file")

	fd, err := os.Open(fname)

	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}

		fd, err = os.Create(fname)
		if err != nil {
			return nil, err
		}

		reader := rand.Reader
		key, err := rsa.GenerateKey(reader, 2048)
		if err != nil {
			return nil, err
		}

		// output the private key
		privOut := new(bytes.Buffer)
		privKey := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}

		if err := pem.Encode(privOut, privKey); err != nil {
			return nil, err
		}

		if _, err := fd.Write(privOut.Bytes()); err != nil {
			return nil, err
		}

		return key, nil
	}

	data, err := ioutil.ReadAll(fd)
	if err != nil {
		return nil, err
	}

	return jwt.ParseRSAPrivateKeyFromPEM(data)
}
