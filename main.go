// Copyright 2021 sjp27 <https://github.com/sjp27>. All rights reserved.
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

// Utility to get the SSH public key from a server.

package main

import (
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/ssh"
	"math/big"
	"net"
	"os"
	"strings"
)

const ssh2Header = "---- BEGIN SSH2 PUBLIC KEY ----"
const ssh2Footer = "---- END SSH2 PUBLIC KEY ----"
const ssh2Width = 70

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: ssh-keyget <host:port> <type(dsa,rsa,ecdsa,ed25519)> <export(e)>")
	} else if len(os.Args) == 3 {
		_ = connectToHost(os.Args[1], os.Args[2], "")
	} else if len(os.Args) == 4 {
		_ = connectToHost(os.Args[1], os.Args[2], os.Args[3])
	} else {
		fmt.Println("Too many arguments")
	}
}

// chunkString convert string to chunks of given size
func chunkString(s string, chunkSize int) []string {
	var chunks []string
	runes := []rune(s)

	if len(runes) == 0 {
		return []string{s}
	}

	for i := 0; i < len(runes); i += chunkSize {
		nn := i + chunkSize
		if nn > len(runes) {
			nn = len(runes)
		}
		chunks = append(chunks, string(runes[i:nn]))
	}
	return chunks
}

// getPublicKeyInfo gets the public key type and length
func getPublicKeyInfo(in []byte) (string, int, error) {
	pk, err := ssh.ParsePublicKey(in)
	if err != nil {
		if strings.Contains(err.Error(), "ssh: unknown key algorithm") {
			return "", 0, err
		}
		return "", 0, fmt.Errorf("ssh.ParsePublicKey: %v", err)
	}
	switch pk.Type() {
	case ssh.KeyAlgoDSA:
		w := struct {
			Name string
			P, Q, G, Y *big.Int
		}{}
		if err := ssh.Unmarshal(pk.Marshal(), &w); err != nil {
			return "", 0, err
		}
		return "dsa", w.P.BitLen(), nil
	case ssh.KeyAlgoRSA:
		w := struct {
			Name string
			E, N *big.Int
		}{}
		if err := ssh.Unmarshal(pk.Marshal(), &w); err != nil {
			return "", 0, err
		}
		return "RSA", w.N.BitLen(), nil
	case ssh.KeyAlgoECDSA256:
		return "ECDSA", 256, nil
	case ssh.KeyAlgoECDSA384:
		return "ECDSA", 384, nil
	case ssh.KeyAlgoECDSA521:
		return "ECDSA", 521, nil
	case ssh.KeyAlgoED25519:
		return "ED25519", 256, nil
	}
	return "", 0, fmt.Errorf("unsupported key type: %s", pk.Type())
}

// trustedHostKeyCallback host key callback from connect
func trustedHostKeyCallback(export string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, k ssh.PublicKey) error {
		ks := base64.StdEncoding.EncodeToString(k.Marshal())

		keytype, length, _ := getPublicKeyInfo(k.Marshal())

		fp := strings.ReplaceAll(ssh.FingerprintLegacyMD5(k), ":", "")

		comment := keytype + " " + fmt.Sprintf("%v", length) + ",MD5:" + fp

		if export == "e" {
			fmt.Println(ssh2Header)
			fmt.Println("Comment: \"" + comment + "\"")
			fmt.Println(strings.Join(chunkString(ks, ssh2Width), "\n"))
			fmt.Println(ssh2Footer)
		} else {
			fmt.Println(k.Type() + " " + ks + " " + comment)
		}
		return nil
	}
}

// connectToHost connect to host to get public key
func connectToHost(host string, keytype string, export string) error {
	sshConfig := &ssh.ClientConfig{
		User:              "",
		Auth:              []ssh.AuthMethod{ssh.Password("")},
		HostKeyCallback:   trustedHostKeyCallback(export),
		HostKeyAlgorithms: []string{ssh.KeyAlgoRSA},
	}

	switch keytype {
	case "dsa":
		sshConfig.HostKeyAlgorithms = []string{ssh.KeyAlgoDSA}
	case "rsa":
		sshConfig.HostKeyAlgorithms = []string{ssh.KeyAlgoRSA}
	case "ecdsa":
		sshConfig.HostKeyAlgorithms = []string{ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521}
	case "ed25519":
		sshConfig.HostKeyAlgorithms = []string{ssh.KeyAlgoED25519}
	default:
		fmt.Println("Unsupported key type")
	}

	client, err := ssh.Dial("tcp", host, sshConfig)
	if err != nil {
		return err
	}

	_ = client.Close()

	return nil
}