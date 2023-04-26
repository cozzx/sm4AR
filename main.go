package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/tjfoc/gmsm/sm4"
)

var (
	KEY string
	IV  string
	T   string
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "sm4",
		Short: "sm4 encryption and decryption program",
		Long:  `you can use "-h" flag to see all subcommands`,

		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			checkParams()
		},
	}

	rootCmd.AddCommand(
		CmdEncrypt,
		CmdDecrypt,
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("Failed to run sm4 with %v: %s", os.Args, err.Error())
		os.Exit(1)
	}
}

func checkParams() {
	if KEY == "" || len(KEY) != 16 || IV == "" {
		fmt.Println("构建程序时请设置KEY和IV参数,KEY长度为16位。T参数为加密类型，默认为ECB，可选CBC,CFB,OFB。")
		fmt.Println(`例如：“go build -o sm4 -ldflags "-X main.KEY=1234123412341234 -X main.IV=0000111122223333 -X main.T=CBC" main.go”。`)
		os.Exit(2)
	}
	sm4.SetIV([]byte(IV))

	if T == "" {
		T = "ECB"
	}
}

var CmdEncrypt = &cobra.Command{
	Use:   "encrypt",
	Short: "Perform parameter encryption",
	Run:   runEncrypt,
	Args:  cobra.ExactArgs(1),
}

func runEncrypt(cmd *cobra.Command, args []string) {
	_T([]byte(args[0]), true)
}

var CmdDecrypt = &cobra.Command{
	Use:   "decrypt",
	Short: "Perform parameter decryption",
	Run:   runDecrypt,
	Args:  cobra.ExactArgs(1),
}

func runDecrypt(cmd *cobra.Command, args []string) {
	b, _ := hex.DecodeString(args[0])
	_T(b, false)
}

func _T(b []byte, en bool) {
	var out []byte
	var src []byte

	switch T {
	case "ECB":
		out, _ = sm4.Sm4Ecb([]byte(KEY), b, en)
		src, _ = sm4.Sm4Ecb([]byte(KEY), out, !en)
	case "CBC":
		out, _ = sm4.Sm4Cbc([]byte(KEY), b, en)
		src, _ = sm4.Sm4Cbc([]byte(KEY), out, !en)
	case "CFB":
		out, _ = sm4.Sm4CFB([]byte(KEY), b, en)
		src, _ = sm4.Sm4CFB([]byte(KEY), out, !en)
	case "OFB":
		out, _ = sm4.Sm4OFB([]byte(KEY), b, en)
		src, _ = sm4.Sm4OFB([]byte(KEY), out, !en)
	}

	if bytes.Equal(b, src) {
		if en {
			fmt.Printf("%x\n", out)
		} else {
			fmt.Printf("%v\n", string(out))
		}
	} else {
		fmt.Println("ERROR")
	}
}
