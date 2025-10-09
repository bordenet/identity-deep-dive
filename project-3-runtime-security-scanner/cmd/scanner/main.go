package main

import (
	"context"
	"fmt"
	"os"

	"github.com/bordenet/identity-deep-dive/project-3-runtime-security-scanner/internal/scanner"
	"github.com/spf13/cobra"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "scanner",
		Short: "A runtime security scanner for OAuth2/OIDC implementations.",
	}

	var runCmd = &cobra.Command{
		Use:   "run [issuer]",
		Short: "Run the scanner against a target issuer.",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			issuer := args[0]
			fmt.Printf("Scanning issuer: %s\n", issuer)

			doc, err := scanner.DiscoverOIDCConfig(context.Background(), issuer)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error discovering OIDC config: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Discovery successful!\n")
			fmt.Printf("  Authorization Endpoint: %s\n", doc.AuthorizationEndpoint)
			fmt.Printf("  Token Endpoint: %s\n", doc.TokenEndpoint)
			fmt.Printf("  JWKS URI: %s\n", doc.JWKSURI)

			scanner := scanner.NewScanner(issuer, doc)
			results := scanner.Run(context.Background())

			fmt.Printf("\nScan results:\n")
			for _, result := range results {
				fmt.Printf("- %s\n", result)
			}
		},
	}

	rootCmd.AddCommand(runCmd)
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
