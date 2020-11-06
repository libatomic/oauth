package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/apex/log"
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

	conn, err := grpc.Dial(c.String("controller-addr"))
	if err != nil {
		return err
	}

	// initialize the api server
	server := server.New(
		rpc.NewClient(conn),
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
