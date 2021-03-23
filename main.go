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
	"strconv"
	"strings"
)

const version = "v1.0"
const sshDefaultPort = 22
const ssh2Header = "---- BEGIN SSH2 PUBLIC KEY ----"
const ssh2Footer = "---- END SSH2 PUBLIC KEY ----"
const ssh2Width = 70

func main() {
	if len(os.Args) < 3 {
		fmt.Println(version + " Usage: ssh-keyget <host:port> <type(dsa,rsa,ecdsa,ed25519)> <export(e)>")
	} else if len(os.Args) == 3 {
		connectToHost(os.Args[1], os.Args[2], "")
	} else if len(os.Args) == 4 {
		connectToHost(os.Args[1], os.Args[2], os.Args[3])
	} else {
		fmt.Println("Too many arguments")
	}
}

// truncateString truncate string to given size
func truncateString(s string, size int) string {
	ts := s
	if len(s) > size {
		ts = s[0:size]
	}
	return ts
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
func trustedHostKeyCallback(host string, export string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, k ssh.PublicKey) error {
		ks := base64.StdEncoding.EncodeToString(k.Marshal())

		keytype, length, _ := getPublicKeyInfo(k.Marshal())

		fpmd5 := ssh.FingerprintLegacyMD5(k)
		fpsha256 := ssh.FingerprintSHA256(k)

		comment := keytype + " " + strconv.Itoa(length) + ", " + host

		if export == "e" {
			fmt.Println(ssh2Header)
			ssh2Comment := "Comment: " + comment
			fmt.Println(truncateString(ssh2Comment, ssh2Width - 1) + "\\")
			fmt.Println("MD5:" + fpmd5 + "\\")
			fmt.Println(fpsha256)
			fmt.Println(strings.Join(chunkString(ks, ssh2Width), "\n"))
			fmt.Println(ssh2Footer)
		} else {
			fmt.Println(k.Type() + " " + ks + " " + comment + ", MD5:" + fpmd5 + ", " + fpsha256)
		}
		return nil
	}
}

// connectToHost connect to host to get public key
func connectToHost(host string, keytype string, export string){
	if !strings.Contains(host, ":")	{
		host = host + ":" + strconv.Itoa(sshDefaultPort)
	}

	sshConfig := &ssh.ClientConfig{
		User:              "",
		Auth:              []ssh.AuthMethod{ssh.Password("")},
		HostKeyCallback:   trustedHostKeyCallback(host, export),
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

	if(len(sshConfig.HostKeyAlgorithms) > 0){
		client, err := ssh.Dial("tcp", host, sshConfig)
		if err == nil {
			_ = client.Close()
		}
	}
}