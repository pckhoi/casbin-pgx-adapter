package pgxadapter

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/mmcloughlin/meow"
)

const (
	DefaultTableName    = "casbin_rule"
	DefaultDatabaseName = "casbin"
	DefaultTimeout      = time.Second * 10
)

// Adapter represents the github.com/jackc/pgx/v4 adapter for policy storage.
type Adapter struct {
	pool            *pgxpool.Pool
	tableName       string
	dbName          string
	schema          string
	timeout         time.Duration
	skipTableCreate bool
	filtered        bool
}

type Filter struct {
	P [][]string
	G [][]string
}

type Option func(a *Adapter)

// NewAdapter creates a new adapter with connection conn which must either be a PostgreSQL
// connection string or an instance of *pgx.ConnConfig from package github.com/jackc/pgx/v4.
func NewAdapter(conn interface{}, opts ...Option) (*Adapter, error) {
	a := &Adapter{
		dbName:    DefaultDatabaseName,
		tableName: DefaultTableName,
		timeout:   DefaultTimeout,
	}
	for _, opt := range opts {
		opt(a)
	}
	pool, err := createDatabase(a.dbName, conn)
	if err != nil {
		return nil, fmt.Errorf("pgxadapter.NewAdapter: %v", err)
	}
	a.pool = pool
	if !a.skipTableCreate {
		if err := a.createTable(); err != nil {
			a.pool.Close()
			return nil, fmt.Errorf("pgxadapter.NewAdapter: %v", err)
		}
	}
	return a, nil
}

// WithTableName can be used to pass custom table name for Casbin rules
func WithTableName(tableName string) Option {
	return func(a *Adapter) {
		a.tableName = tableName
	}
}

// WithSkipTableCreate skips the table creation step when the adapter starts
// If the Casbin rules table does not exist, it will lead to issues when using the adapter
func WithSkipTableCreate() Option {
	return func(a *Adapter) {
		a.skipTableCreate = true
	}
}

// WithDatabase can be used to pass custom database name for Casbin rules
func WithDatabase(dbname string) Option {
	return func(a *Adapter) {
		a.dbName = dbname
	}
}

// WithTimeout can be used to pass a different timeout than DefaultTimeout
// for each request to Postgres
func WithTimeout(timeout time.Duration) Option {
	return func(a *Adapter) {
		a.timeout = timeout
	}
}

// WithSchema can be used to pass a custom schema name. Note that the schema
// name is case-sensitive. If you don't create the schema before hand, the
// schema will be created for you.
func WithSchema(s string) Option {
	return func(a *Adapter) {
		a.schema = s
	}
}

func policyLine(ptype string, values ...string) string {
	const sep = ", "
	var sb strings.Builder
	sb.WriteString(ptype)
	for _, v := range values {
		if len(v) == 0 {
			break
		}
		sb.WriteString(sep)
		sb.WriteString(v)
	}
	return sb.String()
}

func (a *Adapter) tableIdentifier() pgx.Identifier {
	if a.schema != "" {
		return pgx.Identifier{a.schema, a.tableName}
	}
	return pgx.Identifier{a.tableName}
}

func (a *Adapter) schemaTable() string {
	return a.tableIdentifier().Sanitize()
}

// LoadPolicy loads policy from database.
func (a *Adapter) LoadPolicy(model model.Model) error {
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	var pType, v0, v1, v2, v3, v4, v5 pgtype.Text
	_, err := a.pool.QueryFunc(
		ctx,
		fmt.Sprintf(`SELECT "p_type", "v0", "v1", "v2", "v3", "v4", "v5" FROM %s`, a.schemaTable()),
		nil,
		[]interface{}{&pType, &v0, &v1, &v2, &v3, &v4, &v5},
		func(pgx.QueryFuncRow) error {
			persist.LoadPolicyLine(policyLine(pType.String, v0.String, v1.String, v2.String, v3.String, v4.String, v5.String), model)
			return nil
		},
	)
	if err != nil {
		return err
	}

	a.filtered = false

	return nil
}

func policyID(ptype string, rule []string) string {
	data := strings.Join(append([]string{ptype}, rule...), ",")
	sum := meow.Checksum(0, []byte(data))
	return fmt.Sprintf("%x", sum)
}

func policyArgs(ptype string, rule []string) []interface{} {
	row := make([]interface{}, 8)
	row[0] = pgtype.Text{
		String: policyID(ptype, rule),
		Status: pgtype.Present,
	}
	row[1] = pgtype.Text{
		String: ptype,
		Status: pgtype.Present,
	}
	l := len(rule)
	for i := 0; i < 6; i++ {
		if i < l {
			row[2+i] = pgtype.Text{
				String: rule[i],
				Status: pgtype.Present,
			}
		} else {
			row[2+i] = pgtype.Text{
				Status: pgtype.Null,
			}
		}
	}
	return row
}

// SavePolicy saves policy to database.
func (a *Adapter) SavePolicy(model model.Model) error {
	rows := [][]interface{}{}
	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			rows = append(rows, policyArgs(ptype, rule))
		}
	}
	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			rows = append(rows, policyArgs(ptype, rule))
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	return a.pool.BeginFunc(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), fmt.Sprintf("DELETE FROM %s WHERE id IS NOT NULL", a.schemaTable()))
		if err != nil {
			return err
		}
		_, err = tx.CopyFrom(
			context.Background(),
			a.tableIdentifier(),
			[]string{"id", "p_type", "v0", "v1", "v2", "v3", "v4", "v5"},
			pgx.CopyFromRows(rows),
		)
		return err
	})
}

func (a *Adapter) insertPolicyStmt() string {
	return fmt.Sprintf(`
		INSERT INTO %s (id, p_type, v0, v1, v2, v3, v4, v5)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (id) DO NOTHING
	`, a.schemaTable())
}

// AddPolicy adds a policy rule to the storage.
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	_, err := a.pool.Exec(ctx,
		a.insertPolicyStmt(),
		policyArgs(ptype, rule)...,
	)
	return err
}

// AddPolicies adds policy rules to the storage.
func (a *Adapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	return a.pool.BeginFunc(ctx, func(tx pgx.Tx) error {
		b := &pgx.Batch{}
		for _, rule := range rules {
			b.Queue(a.insertPolicyStmt(), policyArgs(ptype, rule)...)
		}
		br := tx.SendBatch(context.Background(), b)
		defer br.Close()
		for range rules {
			_, err := br.Exec()
			if err != nil {
				return err
			}
		}
		return br.Close()
	})
}

// RemovePolicy removes a policy rule from the storage.
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	id := policyID(ptype, rule)
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	_, err := a.pool.Exec(ctx,
		fmt.Sprintf("DELETE FROM %s WHERE id = $1", a.schemaTable()),
		id,
	)
	return err
}

// RemovePolicies removes policy rules from the storage.
func (a *Adapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	return a.pool.BeginFunc(ctx, func(tx pgx.Tx) error {
		b := &pgx.Batch{}
		for _, rule := range rules {
			id := policyID(ptype, rule)
			b.Queue(fmt.Sprintf("DELETE FROM %s WHERE id = $1", a.schemaTable()), id)
		}
		br := tx.SendBatch(context.Background(), b)
		defer br.Close()
		for range rules {
			_, err := br.Exec()
			if err != nil {
				return err
			}
		}
		return br.Close()
	})
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	var sb strings.Builder
	_, err := sb.WriteString(fmt.Sprintf("DELETE FROM %s WHERE p_type = $1", a.schemaTable()))
	if err != nil {
		return err
	}
	args := []interface{}{ptype}

	idx := fieldIndex + len(fieldValues)
	for i := 0; i < 6; i++ {
		if fieldIndex <= i && idx > i && fieldValues[i-fieldIndex] != "" {
			args = append(args, fieldValues[i-fieldIndex])
			_, err = sb.WriteString(fmt.Sprintf(" AND v%d = $%d", i, len(args)))
			if err != nil {
				return err
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	_, err = a.pool.Exec(ctx, sb.String(), args...)
	return err
}

func (a *Adapter) loadFilteredPolicy(model model.Model, filter *Filter, handler func(string, model.Model) error) error {
	var (
		ptype, v0, v1, v2, v3, v4, v5 pgtype.Text
		args                          []interface{}
		sb                            = &strings.Builder{}
	)

	fmt.Fprintf(sb, `SELECT "p_type", "v0", "v1", "v2", "v3", "v4", "v5" FROM %s WHERE `, a.schemaTable())

	buildQuery := func(policies [][]string, ptype string) {
		if len(policies) > 0 {
			args = append(args, ptype)
			fmt.Fprintf(sb, `(p_type = $%d AND (`, len(args))
			for i, p := range policies {
				fmt.Fprint(sb, `(`)
				for j, v := range p {
					if v == "" {
						continue
					}
					args = append(args, v)
					fmt.Fprintf(sb, `v%d = $%d`, j, len(args))
					if j < len(p)-1 {
						fmt.Fprint(sb, ` AND `)
					}
				}
				fmt.Fprint(sb, `)`)
				if i < len(policies)-1 {
					fmt.Fprint(sb, ` OR `)
				}
			}
			fmt.Fprint(sb, `))`)
		}
	}

	buildQuery(filter.P, "p")
	if len(filter.P) > 0 && len(filter.G) > 0 {
		fmt.Fprint(sb, ` OR `)
	}
	buildQuery(filter.G, "g")

	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	_, err := a.pool.QueryFunc(ctx, sb.String(), args, []interface{}{&ptype, &v0, &v1, &v2, &v3, &v4, &v5}, func(qfr pgx.QueryFuncRow) error {
		handler(policyLine(ptype.String, v0.String, v1.String, v2.String, v3.String, v4.String, v5.String), model)
		return nil
	})
	return err
}

// LoadFilteredPolicy can query policies with a filter. Make sure that filter is of type *pgxadapter.Filter
func (a *Adapter) LoadFilteredPolicy(model model.Model, filter interface{}) error {
	if filter == nil {
		return a.LoadPolicy(model)
	}

	filterValue, ok := filter.(*Filter)
	if !ok {
		return fmt.Errorf("filter must be of type *pgxadapter.Filter")
	}
	err := a.loadFilteredPolicy(model, filterValue, persist.LoadPolicyLine)
	if err != nil {
		return err
	}
	a.filtered = true
	return nil
}

func (a *Adapter) IsFiltered() bool {
	return a.filtered
}

// UpdatePolicy updates a policy rule from storage.
// This is part of the Auto-Save feature.
func (a *Adapter) UpdatePolicy(sec string, ptype string, oldRule, newPolicy []string) error {
	return a.UpdatePolicies(sec, ptype, [][]string{oldRule}, [][]string{newPolicy})
}

// UpdatePolicies updates some policy rules to storage, like db, redis.
func (a *Adapter) UpdatePolicies(sec string, ptype string, oldRules, newRules [][]string) error {
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	return a.pool.BeginFunc(ctx, func(t pgx.Tx) error {
		b := &pgx.Batch{}
		for _, rule := range oldRules {
			id := policyID(ptype, rule)
			b.Queue(fmt.Sprintf("DELETE FROM %s WHERE id = $1", a.schemaTable()), id)
		}
		for _, rule := range newRules {
			b.Queue(a.insertPolicyStmt(), policyArgs(ptype, rule)...)
		}
		br := t.SendBatch(context.Background(), b)
		defer br.Close()
		for i := 0; i < b.Len(); i++ {
			_, err := br.Exec()
			if err != nil {
				return err
			}
		}
		return br.Close()
	})
}

// UpdateFilteredPolicies deletes old rules and adds new rules.
func (a *Adapter) UpdateFilteredPolicies(sec string, ptype string, newPolicies [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	return nil, fmt.Errorf("not implemented")
}

func (a *Adapter) Close() {
	if a != nil && a.pool != nil {
		a.pool.Close()
	}
}

func (a *Adapter) createTable() error {
	if a.schema != "" {
		ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
		defer cancel()
		if _, err := a.pool.Exec(ctx, fmt.Sprintf(`CREATE SCHEMA IF NOT EXISTS %s`, pgx.Identifier{a.schema}.Sanitize())); err != nil {
			return err
		}
	}
	lowerTableName := strings.ToLower(a.tableName)
	if a.tableName != DefaultTableName && lowerTableName != a.tableName {
		ident := pgx.Identifier{lowerTableName}
		if a.schema != "" {
			ident = pgx.Identifier{a.schema, lowerTableName}
		}
		exists := false
		ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
		defer cancel()
		if err := a.pool.QueryRow(ctx, fmt.Sprintf(
			"SELECT EXISTS (SELECT COUNT(*) FROM (SELECT FROM %s LIMIT 1) a)",
			ident.Sanitize()),
		).Scan(&exists); err != nil {
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "42P01" {
				return err
			}
		}
		if exists {
			return fmt.Errorf("found table with similar name only in lower case: %q. Either use this table name exactly, or choose a different name", lowerTableName)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	_, err := a.pool.Exec(ctx, fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			id text PRIMARY KEY,
			p_type text,
			v0 text,
			v1 text,
			v2 text,
			v3 text,
			v4 text,
			v5 text
		)
	`, a.schemaTable()))
	return err
}

func createDatabase(dbname string, arg interface{}) (*pgxpool.Pool, error) {
	var conn *pgx.Conn
	var err error
	ctx := context.Background()
	switch v := arg.(type) {
	case string:
		conn, err = pgx.Connect(ctx, v)
		if err != nil {
			return nil, err
		}
	case *pgx.ConnConfig:
		conn, err = pgx.ConnectConfig(ctx, v)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("must pass in a PostgreS URL string or an instance of *pgx.ConnConfig, received %T instead", arg)
	}

	rows, err := conn.Query(ctx, "SELECT FROM pg_database WHERE datname = $1", dbname)
	if err != nil {
		return nil, err
	}
	createdb := !rows.Next()
	rows.Close()

	if createdb {
		_, err = conn.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{dbname}.Sanitize())
		if err != nil {
			return nil, err
		}
	}
	if err := conn.Close(ctx); err != nil {
		return nil, err
	}

	config := conn.Config()
	config.Database = dbname
	if createdb {
		conn, err = pgx.ConnectConfig(ctx, config)
		if err != nil {
			return nil, err
		}
		_, err = conn.Exec(ctx, "create domain uint64 as numeric(20,0)")
		if err != nil {
			return nil, err
		}
		if err := conn.Close(ctx); err != nil {
			return nil, err
		}
	}

	cfg, err := pgxpool.ParseConfig(config.ConnString())
	if err != nil {
		return nil, err
	}
	cfg.ConnConfig.Database = dbname
	return pgxpool.ConnectConfig(ctx, cfg)
}
