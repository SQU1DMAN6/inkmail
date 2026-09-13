package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/SQU1DMAN6/inkmail/internal/database"
	"github.com/SQU1DMAN6/inkmail/internal/identity"
	"github.com/SQU1DMAN6/inkmail/internal/network"
)

const defaultDaddy = "129.150.63.22:25565"

func main() {
	port := flag.Int(
		"port",
		25565,
		"TCP listening port",
	)

	dataDir := flag.String(
		"data",
		filepath.Join(os.Getenv("HOME"), ".inkmail"),
		"InkMail data directory",
	)

	daddy := flag.String(
		"daddy",
		defaultDaddy,
		"address of the Daddy fallback node",
	)

	flag.Parse()

	if err := os.MkdirAll(*dataDir, 0700); err != nil {
		fmt.Fprintf(
			os.Stderr,
			"create data directory: %v\n",
			err,
		)
		os.Exit(1)
	}

	fmt.Println("Starting InkMail Daemon...")

	id, err := identity.LoadOrCreate(
		filepath.Join(*dataDir, "identity"),
	)
	if err != nil {
		fmt.Fprintf(
			os.Stderr,
			"load identity: %v\n",
			err,
		)
		os.Exit(1)
	}

	fmt.Printf(
		"Identity: qchef::%s.ed25519\n",
		identity.Fingerprint(id.PublicKey),
	)

	db, err := database.Open(
		filepath.Join(*dataDir, "node.db"),
	)
	if err != nil {
		fmt.Fprintf(
			os.Stderr,
			"open database: %v\n",
			err,
		)
		os.Exit(1)
	}

	defer db.DB.Close()

	fmt.Printf("Daddy: %s\n", *daddy)

	go func() {
		if err := network.Listen(
			*port,
			id,
			db,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"InkMail listener failed: %v\n",
				err,
			)
			os.Exit(1)
		}
	}()

	if *daddy != "" {
		go network.DialPersistent(
			*daddy,
			id,
			db,
		)
	}

	signals := make(chan os.Signal, 1)

	signal.Notify(
		signals,
		syscall.SIGINT,
		syscall.SIGTERM,
	)

	<-signals

	fmt.Println("Shutting down InkMail...")
}
