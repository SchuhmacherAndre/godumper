package cmd

import (
	"fmt"
	"log"
	"strconv"

	"github.com/schuhmacherandre/godumper/internal/sigscan"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan [pid] [pattern]",
	Short: "Signature scanning, wildcards supported [? or ??]",
	Long: `Scan a remote process for a byte pattern with wildcards.
Example:
  godumper scan 1234 48 8B ?? 24`,
	Args: cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		scan(args)
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
}

func scan(args []string) {
	pid := args[0]

	rawPattern := args[1:]
	pattern := []byte{}
	wildcard := byte(0xFF)

	for _, s := range rawPattern {
		if s == "?" || s == "??" {
			pattern = append(pattern, wildcard)
		} else {
			b, err := strconv.ParseUint(s, 16, 8)
			if err != nil {
				log.Fatalf("Invalid pattern byte '%s': %v", s, err)
			}
			pattern = append(pattern, byte(b))
		}
	}

	scanner, err := sigscan.NewScanner(pid)
	if err != nil {
		log.Fatalf("Failed to open process: %v", err)
	}
	defer scanner.Close()

	matches, err := scanner.ScanAll(pattern, wildcard)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	if len(matches) == 0 {
		fmt.Println("No matches found.")
		return
	}

	fmt.Println("Matches found at:")
	for _, addr := range matches {
		fmt.Printf("  0x%X\n", addr)
	}
}
