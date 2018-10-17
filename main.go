package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/hashicorp/vault/api"
)

var (
	Login      = flag.String("login", "", "User's login")
	Password   = flag.String("password", "", "User's password")
	AuthMethod = flag.String("method", "ldap", "Auth method")
	VaultAddr  = flag.String("vault", "", "Vault's address")
	WrapTTL    = flag.Duration("wrap-ttl", 5*time.Minute, "")
	Read       = flag.Bool("read", false, "Read data")
)

func NewClient(addr, user, pass, authMethod string) (*api.Client, []string, error) {
	config := api.Config{
		Address: addr,
	}
	client, err := api.NewClient(&config)
	if err != nil {
		return nil, nil, err
	}
	options := map[string]interface{}{
		"password": pass,
	}
	path := fmt.Sprintf("auth/%s/login/%s", authMethod, user)
	secret, err := client.Logical().Write(path, options)
	if err != nil {
		return nil, nil, err
	}
	client.SetToken(secret.Auth.ClientToken)
	return client, secret.Auth.Policies, nil
}

func DefaultWrappingLookupFunc(operation, path string) string {
	if *WrapTTL != 0 {
		return WrapTTL.String()
	}
	return api.DefaultWrappingLookupFunc(operation, path)
}

func main() {
	flag.Parse()
	cli, policies, err := NewClient(*VaultAddr, *Login, *Password, *AuthMethod)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Policies: %v\n", policies)
	cli.SetWrappingLookupFunc(DefaultWrappingLookupFunc)
	secret, err := cli.Logical().Write("sys/wrapping/wrap", map[string]interface{}{
		"time": time.Now().UTC().String(),
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("%#v\n", secret.WrapInfo.Token)
}
