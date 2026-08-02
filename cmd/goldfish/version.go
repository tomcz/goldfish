package main

import (
	"fmt"

	"github.com/alecthomas/kong"
)

// set by build
var version string

type versionFlag bool

func (v versionFlag) IgnoreDefault() {}

func (v versionFlag) BeforeReset(c *kong.Context) error {
	fmt.Println(version)
	c.Exit(0)
	return nil
}
