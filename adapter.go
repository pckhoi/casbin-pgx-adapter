package pgxadapter

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mmcloughlin/meow"
)

const (
	DefaultTableName    = "casbin_rule"
	DefaultDatabaseName = "casbin"
	DefaultTimeout      = time.Second * 10
)

// Adapter represents the github.com/jackc/pgx/v5 adapter for policy storage.
// Adapter is not safe for concurrent use by multiple enforcers; use one Adapter per enforcer or synchronize externally.
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
	P      [][]string
	G      [][]string
	Ptypes map[string][][]string
}

type Option func(a *Adapter)

// The adapter satisfies both the plain and the context-aware casbin
// persistence interfaces.
var (
	_ persist.Adapter                 = (*Adapter)(nil)
	_ persist.FilteredAdapter         = (*Adapter)(nil)
	_ persist.BatchAdapter            = (*Adapter)(nil)
	_ persist.UpdatableAdapter        = (*Adapter)(nil)
	_ persist.ContextAdapter          = (*Adapter)(nil)
	_ persist.ContextFilteredAdapter  = (*Adapter)(nil)
	_ persist.ContextBatchAdapter     = (*Adapter)(nil)
	_ persist.ContextUpdatableAdapter = (*Adapter)(nil)
)

// NewAdapter creates a new adapter with connection conn which must either be a PostgreSQL
// connection string or an instance of *pgx.ConnConfig from package github.com/jackc/pgx/v5.
func NewAdapter(conn interface{}, opts ...Option) (*Adapter, error) {
	a := &Adapter{
		dbName:    DefaultDatabaseName,
		tableName: DefaultTableName,
		timeout:   DefaultTimeout,
	}
	for _, opt := range opts {
		opt(a)
	}

	if a.pool == nil {
		pool, err := createDatabase(a.dbName, conn)
		if err != nil {
			return nil, fmt.Errorf("pgxadapter.NewAdapter: %v", err)
		}
		a.pool = pool
	}

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

// WithConnectionPool can be used to pass an existing *pgxpool.Pool instance
func WithConnectionPool(pool *pgxpool.Pool) Option {
	return func(a *Adapter) {
		a.pool = pool
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

func policyArray(ptype string, values ...string) []string {
	rule := make([]string, 1, 7)
	rule[0] = ptype
	for _, v := range values {
		if v == "" {
			break
		}
		rule = append(rule, v)
	}
	return rule
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
	return a.LoadPolicyCtx(context.Background(), model)
}

// LoadPolicyCtx loads all policy rules from the storage with context.
func (a *Adapter) LoadPolicyCtx(ctx context.Context, model model.Model) error {
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	var pType, v0, v1, v2, v3, v4, v5 pgtype.Text
	rows, err := a.pool.Query(ctx, fmt.Sprintf(`SELECT "p_type", "v0", "v1", "v2", "v3", "v4", "v5" FROM %s`, a.schemaTable()))
	if err != nil {
		return err
	}
	_, err = pgx.ForEachRow(rows, []any{&pType, &v0, &v1, &v2, &v3, &v4, &v5}, func() error {
		return persist.LoadPolicyArray(policyArray(pType.String, v0.String, v1.String, v2.String, v3.String, v4.String, v5.String), model)
	})
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

func policyArgs(ptype string, rule []string) []any {
	// nil encodes as NULL for the columns beyond the rule's length
	row := []any{policyID(ptype, rule), ptype, nil, nil, nil, nil, nil, nil}
	for i := 0; i < len(rule) && i < 6; i++ {
		row[2+i] = rule[i]
	}
	return row
}

// SavePolicy saves policy to database.
func (a *Adapter) SavePolicy(model model.Model) error {
	return a.SavePolicyCtx(context.Background(), model)
}

// SavePolicyCtx saves all policy rules to the storage with context.
func (a *Adapter) SavePolicyCtx(ctx context.Context, model model.Model) error {
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	if a.filtered {
		return errors.New("cannot save a filtered policy")
	}
	rows := [][]any{}
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

	return pgx.BeginFunc(ctx, a.pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, fmt.Sprintf("DELETE FROM %s WHERE id IS NOT NULL", a.schemaTable()))
		if err != nil {
			return err
		}
		_, err = tx.CopyFrom(
			ctx,
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
	return a.AddPolicyCtx(context.Background(), sec, ptype, rule)
}

// AddPolicyCtx adds a policy rule to the storage with context.
func (a *Adapter) AddPolicyCtx(ctx context.Context, sec string, ptype string, rule []string) error {
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	_, err := a.pool.Exec(ctx, a.insertPolicyStmt(), policyArgs(ptype, rule)...)
	return err
}

// AddPolicies adds policy rules to the storage.
func (a *Adapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	return a.AddPoliciesCtx(context.Background(), sec, ptype, rules)
}

// AddPoliciesCtx adds policy rules to the storage with context.
func (a *Adapter) AddPoliciesCtx(ctx context.Context, sec string, ptype string, rules [][]string) error {
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	return pgx.BeginFunc(ctx, a.pool, func(tx pgx.Tx) error {
		b := &pgx.Batch{}
		for _, rule := range rules {
			b.Queue(a.insertPolicyStmt(), policyArgs(ptype, rule)...)
		}
		br := tx.SendBatch(ctx, b)
		for range rules {
			_, err := br.Exec()
			if err != nil {
				br.Close()
				return err
			}
		}
		return br.Close()
	})
}

// RemovePolicy removes a policy rule from the storage.
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	return a.RemovePolicyCtx(context.Background(), sec, ptype, rule)
}

// RemovePolicyCtx removes a policy rule from the storage with context.
func (a *Adapter) RemovePolicyCtx(ctx context.Context, sec string, ptype string, rule []string) error {
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	id := policyID(ptype, rule)
	_, err := a.pool.Exec(ctx,
		fmt.Sprintf("DELETE FROM %s WHERE id = $1", a.schemaTable()),
		id,
	)
	return err
}

// RemovePolicies removes policy rules from the storage.
func (a *Adapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	return a.RemovePoliciesCtx(context.Background(), sec, ptype, rules)
}

// RemovePoliciesCtx removes policy rules from the storage with context.
func (a *Adapter) RemovePoliciesCtx(ctx context.Context, sec string, ptype string, rules [][]string) error {
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	return pgx.BeginFunc(ctx, a.pool, func(tx pgx.Tx) error {
		b := &pgx.Batch{}
		for _, rule := range rules {
			b.Queue(fmt.Sprintf("DELETE FROM %s WHERE id = $1", a.schemaTable()), policyID(ptype, rule))
		}
		br := tx.SendBatch(ctx, b)
		for range rules {
			_, err := br.Exec()
			if err != nil {
				br.Close()
				return err
			}
		}
		return br.Close()
	})
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	return a.RemoveFilteredPolicyCtx(context.Background(), sec, ptype, fieldIndex, fieldValues...)
}

// RemoveFilteredPolicyCtx removes policy rules that match the filter from the storage with context.
func (a *Adapter) RemoveFilteredPolicyCtx(ctx context.Context, sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	where, args := a.filteredWhere(ptype, fieldIndex, fieldValues)
	_, err := a.pool.Exec(ctx, fmt.Sprintf("DELETE FROM %s", a.schemaTable())+where, args...)
	return err
}

// filteredWhere builds " WHERE p_type = $1 [AND vN = $n ...]" and its
// arguments from a casbin filtered-operation selector. Empty fieldValues are
// skipped (match any).
func (a *Adapter) filteredWhere(ptype string, fieldIndex int, fieldValues []string) (string, []any) {
	var sb strings.Builder
	sb.WriteString(" WHERE p_type = $1")
	args := []any{ptype}
	for i, v := range fieldValues {
		col := fieldIndex + i
		if col > 5 {
			break
		}
		if v == "" {
			continue
		}
		args = append(args, v)
		fmt.Fprintf(&sb, " AND v%d = $%d", col, len(args))
	}
	return sb.String(), args
}

func (a *Adapter) filterQuery(filter *Filter) (string, []any) {
	groups := map[string][][]string{}
	if len(filter.P) > 0 {
		groups["p"] = append(groups["p"], filter.P...)
	}
	if len(filter.G) > 0 {
		groups["g"] = append(groups["g"], filter.G...)
	}
	for ptype, patterns := range filter.Ptypes {
		if len(patterns) > 0 {
			groups[ptype] = append(groups[ptype], patterns...)
		}
	}

	ptypes := slices.Sorted(maps.Keys(groups))

	var args []any
	groupClauses := make([]string, 0, len(groups))
	for _, ptype := range ptypes {
		args = append(args, ptype)
		ptypeCond := fmt.Sprintf("p_type = $%d", len(args))

		matchAll := false
		for _, pattern := range groups[ptype] {
			nonEmpty := false
			for _, v := range pattern {
				if v != "" {
					nonEmpty = true
					break
				}
			}
			if !nonEmpty {
				matchAll = true
				break
			}
		}
		if matchAll {
			groupClauses = append(groupClauses, "("+ptypeCond+")")
			continue
		}

		patternClauses := make([]string, 0, len(groups[ptype]))
		for _, pattern := range groups[ptype] {
			var conds []string
			for i, v := range pattern {
				if i > 5 {
					break
				}
				if v == "" {
					continue
				}
				args = append(args, v)
				conds = append(conds, fmt.Sprintf("v%d = $%d", i, len(args)))
			}
			patternClauses = append(patternClauses, "("+strings.Join(conds, " AND ")+")")
		}
		groupClauses = append(groupClauses, "("+ptypeCond+" AND ("+strings.Join(patternClauses, " OR ")+"))")
	}

	query := fmt.Sprintf(`SELECT "p_type", "v0", "v1", "v2", "v3", "v4", "v5" FROM %s`, a.schemaTable())
	if len(groupClauses) > 0 {
		query += " WHERE " + strings.Join(groupClauses, " OR ")
	}
	return query, args
}

func (a *Adapter) loadFilteredPolicy(ctx context.Context, model model.Model, filter *Filter) error {
	query, args := a.filterQuery(filter)
	rows, err := a.pool.Query(ctx, query, args...)
	if err != nil {
		return err
	}
	var ptype, v0, v1, v2, v3, v4, v5 pgtype.Text
	_, err = pgx.ForEachRow(rows, []any{&ptype, &v0, &v1, &v2, &v3, &v4, &v5}, func() error {
		return persist.LoadPolicyArray(policyArray(ptype.String, v0.String, v1.String, v2.String, v3.String, v4.String, v5.String), model)
	})
	return err
}

// LoadFilteredPolicy can query policies with a filter.
func (a *Adapter) LoadFilteredPolicy(model model.Model, filter any) error {
	return a.LoadFilteredPolicyCtx(context.Background(), model, filter)
}

// LoadFilteredPolicyCtx can query policies with a filter with context.
func (a *Adapter) LoadFilteredPolicyCtx(ctx context.Context, model model.Model, filter any) error {
	if filter == nil {
		return a.LoadPolicyCtx(ctx, model)
	}

	filterValue, ok := filter.(*Filter)
	if !ok {
		return fmt.Errorf("filter must be of type *pgxadapter.Filter")
	}
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	err := a.loadFilteredPolicy(ctx, model, filterValue)
	if err != nil {
		return err
	}
	a.filtered = true
	return nil
}

// IsFiltered returns true if the loaded policy has been filtered.
func (a *Adapter) IsFiltered() bool {
	return a.IsFilteredCtx(context.Background())
}

// IsFilteredCtx returns true if the loaded policy has been filtered.
func (a *Adapter) IsFilteredCtx(ctx context.Context) bool {
	return a.filtered
}

// UpdatePolicy updates a policy rule from storage.
func (a *Adapter) UpdatePolicy(sec string, ptype string, oldRule, newPolicy []string) error {
	return a.UpdatePolicyCtx(context.Background(), sec, ptype, oldRule, newPolicy)
}

// UpdatePolicyCtx updates a policy rule from storage with context.
func (a *Adapter) UpdatePolicyCtx(ctx context.Context, sec string, ptype string, oldRule, newPolicy []string) error {
	return a.UpdatePoliciesCtx(ctx, sec, ptype, [][]string{oldRule}, [][]string{newPolicy})
}

// UpdatePolicies updates some policy rules to storage, like db, redis.
func (a *Adapter) UpdatePolicies(sec string, ptype string, oldRules, newRules [][]string) error {
	return a.UpdatePoliciesCtx(context.Background(), sec, ptype, oldRules, newRules)
}

// UpdatePoliciesCtx updates some policy rules to storage, like db, redis, with context.
func (a *Adapter) UpdatePoliciesCtx(ctx context.Context, sec string, ptype string, oldRules, newRules [][]string) error {
	if len(oldRules) != len(newRules) {
		return errors.New("old rules size not equal to new rules size")
	}
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	return pgx.BeginFunc(ctx, a.pool, func(tx pgx.Tx) error {
		b := &pgx.Batch{}
		for _, rule := range oldRules {
			b.Queue(fmt.Sprintf("DELETE FROM %s WHERE id = $1", a.schemaTable()), policyID(ptype, rule))
		}
		for _, rule := range newRules {
			b.Queue(a.insertPolicyStmt(), policyArgs(ptype, rule)...)
		}
		br := tx.SendBatch(ctx, b)
		for i := 0; i < b.Len(); i++ {
			_, err := br.Exec()
			if err != nil {
				br.Close()
				return err
			}
		}
		return br.Close()
	})
}

// UpdateFilteredPolicies deletes old rules matching the filter and adds new rules in a single transaction.
func (a *Adapter) UpdateFilteredPolicies(sec string, ptype string, newRules [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	return a.UpdateFilteredPoliciesCtx(context.Background(), sec, ptype, newRules, fieldIndex, fieldValues...)
}

// UpdateFilteredPoliciesCtx deletes old rules matching the filter and adds new rules in a single transaction, with context.
func (a *Adapter) UpdateFilteredPoliciesCtx(ctx context.Context, sec string, ptype string, newRules [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	where, args := a.filteredWhere(ptype, fieldIndex, fieldValues)
	query := fmt.Sprintf("DELETE FROM %s", a.schemaTable()) + where + " RETURNING v0, v1, v2, v3, v4, v5"

	var oldRules [][]string
	err := pgx.BeginFunc(ctx, a.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		var v0, v1, v2, v3, v4, v5 pgtype.Text
		if _, err = pgx.ForEachRow(rows, []any{&v0, &v1, &v2, &v3, &v4, &v5}, func() error {
			rule := make([]string, 0, 6)
			for _, v := range []string{v0.String, v1.String, v2.String, v3.String, v4.String, v5.String} {
				if v == "" {
					break
				}
				rule = append(rule, v)
			}
			oldRules = append(oldRules, rule)
			return nil
		}); err != nil {
			return err
		}

		b := &pgx.Batch{}
		for _, rule := range newRules {
			b.Queue(a.insertPolicyStmt(), policyArgs(ptype, rule)...)
		}
		br := tx.SendBatch(ctx, b)
		for range newRules {
			if _, err := br.Exec(); err != nil {
				br.Close()
				return err
			}
		}
		return br.Close()
	})
	if err != nil {
		return nil, err
	}
	return oldRules, nil
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
		if err := a.pool.QueryRow(ctx,
			"SELECT to_regclass($1) IS NOT NULL", ident.Sanitize(),
		).Scan(&exists); err != nil {
			return err
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

func createDatabase(dbname string, arg any) (*pgxpool.Pool, error) {
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
	return pgxpool.NewWithConfig(ctx, cfg)
}
