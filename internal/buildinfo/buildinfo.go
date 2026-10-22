// Package buildinfo contains linker-overridable version metadata shared by ARAP executables.
package buildinfo

import "encoding/json"

var Version = "dev"
var Commit = "unknown"

type Info struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

func For(name string) Info { return Info{Name: name, Version: Version, Commit: Commit} }

func JSON(name string) ([]byte, error) { return json.Marshal(For(name)) }
