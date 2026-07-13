# PGX Adapter

[![Tests](https://github.com/pckhoi/casbin-pgx-adapter/actions/workflows/ci.yml/badge.svg)](https://github.com/pckhoi/casbin-pgx-adapter/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/pckhoi/casbin-pgx-adapter/badge.svg?branch=main)](https://coveralls.io/github/pckhoi/casbin-pgx-adapter?branch=main)

PGX Adapter is the [pgx](https://github.com/jackc/pgx) adapter for [Casbin](https://github.com/casbin/casbin). With this library, Casbin can load policy from PostgreSQL or save policy to it.

Requires Casbin v3. The adapter also implements Casbin's context-aware interfaces (`LoadPolicyCtx`, `AddPolicyCtx`, ...), so every operation can be bounded by a caller-supplied `context.Context`.

## Installation

    go get github.com/pckhoi/casbin-pgx-adapter/v3

## Simple Postgres Example

```go
package main

import (
	pgxadapter "github.com/pckhoi/casbin-pgx-adapter/v3"
	"github.com/casbin/casbin/v3"
)

func main() {
	// Initialize a PGX adapter and use it in a Casbin enforcer:
	// The adapter will use the Postgres database named "casbin".
	// If it doesn't exist, the adapter will create it automatically.
	a, _ := pgxadapter.NewAdapter("postgresql://username:password@postgres:5432/database?sslmode=disable") // Your driver and data source.
	// Alternatively, you can construct an adapter instance with *pgx.ConnConfig:
    // conf, _ := pgx.ParseConfig("postgresql://pguser:pgpassword@localhost:5432/pgdb?sslmode=disable")
	// a, _ := pgxadapter.NewAdapter(conf)

	// The adapter will use the table named "casbin_rule" by default.
	// If it doesn't exist, the adapter will create it automatically.

	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)

	// Load the policy from DB.
	e.LoadPolicy()

	// Check the permission.
	e.Enforce("alice", "data1", "read")

	// Modify the policy.
	// e.AddPolicy(...)
	// e.RemovePolicy(...)

	// Save the policy back to DB.
	e.SavePolicy()
}
```

## Support for FilteredAdapter interface

You can [load a subset of policies](https://casbin.org/docs/en/policy-subset-loading) with this adapter:

```go
package main

import (
	"github.com/casbin/casbin/v3"
	pgxadapter "github.com/pckhoi/casbin-pgx-adapter/v3"
)

func main() {
	a, _ := pgxadapter.NewAdapter("postgresql://username:password@postgres:5432/database?sslmode=disable")
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)

	e.LoadFilteredPolicy(&pgxadapter.Filter{
		P: [][]string{{"", "data1"}},
		G: [][]string{{"alice"}},
		// Ptypes filters additional policy types (e.g. "p2", "g2")
		// Ptypes: map[string][][]string{"p2": {{"alice"}}},
	})
	...
}
```

## Custom database name and table name

You can provide a custom table or database name with option functions

```go
package main

import (
	"github.com/casbin/casbin/v3"
	pgxadapter "github.com/pckhoi/casbin-pgx-adapter/v3"
	"github.com/jackc/pgx/v5"
)

func main() {
    conf, _ := pgx.ParseConfig("postgresql://pguser:pgpassword@localhost:5432/pgdb?sslmode=disable")

    a, _ := pgxadapter.NewAdapter(conf,
        pgxadapter.WithDatabase("custom_database"),
        pgxadapter.WithTableName("custom_table"),
    )
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)
    ...
}
```

## Run all tests

    PG_CONN=postgresql://user:password@localhost:5432/testdb?sslmode=disable go test github.com/pckhoi/casbin-pgx-adapter -coverpkg=./...

## Getting Help

- [Casbin](https://github.com/casbin/casbin)

## License

This project is under Apache 2.0 License. See the [LICENSE](LICENSE) file for the full license text.
