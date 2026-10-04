module github.com/rett/tacctl

go 1.26.0

// tests/fixtures/tacquito-src holds upstream tacquito files the patch tests
// apply patches/ to; they are not part of this module.
ignore ./tests/fixtures

require (
	github.com/spf13/cobra v1.10.2
	golang.org/x/crypto v0.57.0
	golang.org/x/sys v0.48.0
	golang.org/x/term v0.46.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
)
