package pgxadapter

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/util"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func dropDB(t *testing.T, dbname string) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("PG_CONN"))
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "DROP DATABASE "+dbname)
	require.NoError(t, err)
	require.NoError(t, conn.Close(ctx))
}

func assertPolicy(t *testing.T, expected, res [][]string) {
	t.Helper()
	assert.True(t, util.Array2DEquals(expected, res), "Policy Got: %v, supposed to be %v", res, expected)
}

func testSaveLoad(t *testing.T, a *Adapter, e *casbin.Enforcer) {
	assert.False(t, e.IsFiltered())
	res, err := e.GetPolicy()
	require.NoError(t, err)
	assertPolicy(t,
		[][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}},
		res,
	)
}

func testAutoSave(t *testing.T, a *Adapter, e *casbin.Enforcer) {
	// AutoSave is enabled by default.
	// Now we disable it.
	e.EnableAutoSave(false)

	// Because AutoSave is disabled, the policy change only affects the policy in Casbin enforcer,
	// it doesn't affect the policy in the storage.
	_, err := e.AddPolicy("alice", "data1", "write")
	require.NoError(t, err)
	// Reload the policy from the storage to see the effect.
	err = e.LoadPolicy()
	require.NoError(t, err)
	// This is still the original policy.
	res, err := e.GetPolicy()
	require.NoError(t, err)
	assertPolicy(t,
		[][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}},
		res,
	)

	// Now we enable the AutoSave.
	e.EnableAutoSave(true)

	// Because AutoSave is enabled, the policy change not only affects the policy in Casbin enforcer,
	// but also affects the policy in the storage.
	_, err = e.AddPolicy("alice", "data1", "write")
	require.NoError(t, err)
	// Reload the policy from the storage to see the effect.
	err = e.LoadPolicy()
	require.NoError(t, err)
	// The policy has a new rule: {"alice", "data1", "write"}.
	res, err = e.GetPolicy()
	require.NoError(t, err)
	assertPolicy(t,
		[][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"alice", "data1", "write"}},
		res,
	)

	// Aditional AddPolicy have no effect
	_, err = e.AddPolicy("alice", "data1", "write")
	require.NoError(t, err)
	err = e.LoadPolicy()
	require.NoError(t, err)
	res, err = e.GetPolicy()
	require.NoError(t, err)
	assertPolicy(t,
		[][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"alice", "data1", "write"}},
		res,
	)

	_, err = e.AddPolicies([][]string{
		{"bob", "data2", "read"},
		{"alice", "data2", "write"},
		{"alice", "data2", "read"},
		{"bob", "data1", "write"},
		{"bob", "data1", "read"},
	})
	require.NoError(t, err)
	// Reload the policy from the storage to see the effect.
	err = e.LoadPolicy()
	require.NoError(t, err)
	// The policy has a new rule: {"alice", "data1", "write"}.
	res, err = e.GetPolicy()
	require.NoError(t, err)
	assertPolicy(t,
		[][]string{
			{"alice", "data1", "read"},
			{"bob", "data2", "write"},
			{"data2_admin", "data2", "read"},
			{"data2_admin", "data2", "write"},
			{"alice", "data1", "write"},
			{"bob", "data2", "read"},
			{"alice", "data2", "write"},
			{"alice", "data2", "read"},
			{"bob", "data1", "write"},
			{"bob", "data1", "read"},
		},
		res,
	)

	require.NoError(t, err)
}

func testCustomDatabaseAndTableName(t *testing.T, a *Adapter, e *casbin.Enforcer) {
	cfg, err := pgx.ParseConfig(os.Getenv("PG_CONN"))
	require.NoError(t, err)
	cfg.Database = "test_pgxadapter"
	conn, err := pgx.ConnectConfig(context.Background(), cfg)
	require.NoError(t, err)
	defer conn.Close(context.Background())

	var v0, v1, v2 string
	policies := [][]string{}
	rows, err := conn.Query(context.Background(), "SELECT v0, v1, v2 FROM test_casbin_rules WHERE p_type = $1", "p")
	require.NoError(t, err)
	pgx.ForEachRow(rows, []interface{}{&v0, &v1, &v2}, func() error {
		policies = append(policies, []string{v0, v1, v2})
		return nil
	})
	assert.Equal(t, [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"}},
		policies,
	)
}

func testRemovePolicy(t *testing.T, a *Adapter, e *casbin.Enforcer) {
	_, err := e.RemovePolicy("alice", "data1", "read")
	require.NoError(t, err)

	res, err := e.GetPolicy()
	require.NoError(t, err)
	assertPolicy(t,
		[][]string{{"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}},
		res,
	)

	err = e.LoadPolicy()
	require.NoError(t, err)

	res, err = e.GetPolicy()
	require.NoError(t, err)
	assertPolicy(t,
		[][]string{{"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}},
		res,
	)

	_, err = e.RemovePolicies([][]string{
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
	})
	require.NoError(t, err)

	res, err = e.GetPolicy()
	require.NoError(t, err)
	assertPolicy(t,
		[][]string{{"bob", "data2", "write"}},
		res,
	)
}

func testRemoveFilteredPolicy(t *testing.T, a *Adapter, e *casbin.Enforcer) {
	_, err := e.RemoveFilteredPolicy(0, "", "data2")
	require.NoError(t, err)

	res, err := e.GetPolicy()
	require.NoError(t, err)
	assertPolicy(t,
		[][]string{{"alice", "data1", "read"}},
		res,
	)

	err = e.LoadPolicy()
	require.NoError(t, err)

	res, err = e.GetPolicy()
	require.NoError(t, err)
	assertPolicy(t,
		[][]string{{"alice", "data1", "read"}},
		res,
	)
}

func testRemoveFilteredGroupingPolicy(t *testing.T, a *Adapter, e *casbin.Enforcer) {
	e.AddGroupingPolicy("bob", "data2_admin")
	res, err := e.GetGroupingPolicy()
	require.NoError(t, err)
	assertPolicy(t,
		[][]string{{"alice", "data2_admin"}, {"bob", "data2_admin"}},
		res,
	)

	_, err = e.RemoveFilteredGroupingPolicy(0, "alice")
	require.NoError(t, err)

	res, err = e.GetGroupingPolicy()
	require.NoError(t, err)
	assertPolicy(t,
		[][]string{{"bob", "data2_admin"}},
		res,
	)

	err = e.LoadPolicy()
	require.NoError(t, err)
	res, err = e.GetGroupingPolicy()
	require.NoError(t, err)
	assertPolicy(t,
		[][]string{{"bob", "data2_admin"}},
		res,
	)
}

func testLoadFilteredPolicy(t *testing.T, a *Adapter, e *casbin.Enforcer) {
	e, err := casbin.NewEnforcer("testdata/rbac_model.conf", a)
	require.NoError(t, err)
	err = e.LoadFilteredPolicy(&Filter{
		P: [][]string{{"", "", "read"}},
	})
	require.NoError(t, err)
	assert.True(t, e.IsFiltered())
	res, err := e.GetPolicy()
	require.NoError(t, err)
	assertPolicy(t,
		[][]string{{"alice", "data1", "read"}, {"data2_admin", "data2", "read"}},
		res,
	)

	// load multiple policy patterns at once
	e, err = casbin.NewEnforcer("testdata/rbac_model.conf", a)
	require.NoError(t, err)
	err = e.LoadFilteredPolicy(&Filter{
		P: [][]string{{"", "", "read"}, {"data2_admin"}},
	})
	require.NoError(t, err)
	assert.True(t, e.IsFiltered())
	res, err = e.GetPolicy()
	require.NoError(t, err)
	assertPolicy(t,
		[][]string{{"alice", "data1", "read"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}},
		res,
	)
}

func testLoadFilteredGroupingPolicy(t *testing.T, a *Adapter, e *casbin.Enforcer) {
	e, err := casbin.NewEnforcer("testdata/rbac_model.conf", a)
	require.NoError(t, err)

	err = e.LoadFilteredPolicy(&Filter{
		G: [][]string{{"bob"}},
	})
	require.NoError(t, err)
	assert.True(t, e.IsFiltered())
	res, err := e.GetGroupingPolicy()
	require.NoError(t, err)
	assertPolicy(t, [][]string{}, res)

	e, err = casbin.NewEnforcer("testdata/rbac_model.conf", a)
	require.NoError(t, err)

	err = e.LoadFilteredPolicy(&Filter{
		G: [][]string{{"alice"}},
	})
	require.NoError(t, err)
	assert.True(t, e.IsFiltered())
	res, err = e.GetGroupingPolicy()
	require.NoError(t, err)
	assertPolicy(t, [][]string{{"alice", "data2_admin"}}, res)
}

func testLoadFilteredPolicyNilFilter(t *testing.T, a *Adapter, e *casbin.Enforcer) {
	e, err := casbin.NewEnforcer("testdata/rbac_model.conf", a)
	require.NoError(t, err)

	err = e.LoadFilteredPolicy(nil)
	require.NoError(t, err)

	assert.False(t, e.IsFiltered())
	res, err := e.GetPolicy()
	require.NoError(t, err)
	assertPolicy(t,
		[][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}},
		res,
	)
}

func testSavePolicyClearPreviousData(t *testing.T, a *Adapter, e *casbin.Enforcer) {
	e.EnableAutoSave(false)
	policies, err := e.GetPolicy()
	require.NoError(t, err)
	// clone slice to avoid shufling elements
	policies = append(policies[:0:0], policies...)
	for _, p := range policies {
		_, err := e.RemovePolicy(p)
		require.NoError(t, err)
	}
	policies, err = e.GetGroupingPolicy()
	require.NoError(t, err)
	policies = append(policies[:0:0], policies...)
	for _, p := range policies {
		_, err := e.RemoveGroupingPolicy(p)
		require.NoError(t, err)
	}
	res, err := e.GetPolicy()
	require.NoError(t, err)
	assertPolicy(t,
		[][]string{},
		res,
	)

	err = e.SavePolicy()
	require.NoError(t, err)

	err = e.LoadPolicy()
	require.NoError(t, err)
	res, err = e.GetPolicy()
	require.NoError(t, err)
	assertPolicy(t,
		[][]string{},
		res,
	)
}

func testUpdatePolicy(t *testing.T, a *Adapter, e *casbin.Enforcer) {
	var err error
	e, err = casbin.NewEnforcer("testdata/rbac_model.conf", "testdata/rbac_policy.csv")
	require.NoError(t, err)

	e.SetAdapter(a)

	err = e.SavePolicy()
	require.NoError(t, err)

	_, err = e.UpdatePolicies([][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}}, [][]string{{"bob", "data1", "read"}, {"alice", "data2", "write"}})
	require.NoError(t, err)

	err = e.LoadPolicy()
	require.NoError(t, err)

	res, err := e.GetPolicy()
	require.NoError(t, err)
	assertPolicy(t, res, [][]string{{"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"bob", "data1", "read"}, {"alice", "data2", "write"}})

	_, err = e.UpdatePolicy([]string{"bob", "data1", "read"}, []string{"alice", "data1", "read"})
	require.NoError(t, err)

	res, err = e.GetPolicy()
	require.NoError(t, err)
	assertPolicy(t, res, [][]string{{"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"alice", "data1", "read"}, {"alice", "data2", "write"}})
}

func testUpdatePolicyWithLoadFilteredPolicy(t *testing.T, a *Adapter, e *casbin.Enforcer) {
	var err error
	e, err = casbin.NewEnforcer("testdata/rbac_model.conf", "testdata/rbac_policy.csv")
	require.NoError(t, err)

	e.SetAdapter(a)

	err = e.SavePolicy()
	require.NoError(t, err)

	err = e.LoadFilteredPolicy(&Filter{P: [][]string{{"data2_admin"}}})
	require.NoError(t, err)

	res, err := e.GetPolicy()
	require.NoError(t, err)
	_, err = e.UpdatePolicies(res, [][]string{{"bob", "data2", "read"}, {"alice", "data2", "write"}})
	require.NoError(t, err)

	err = e.LoadPolicy()
	require.NoError(t, err)

	res, err = e.GetPolicy()
	require.NoError(t, err)
	assertPolicy(t, res, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"bob", "data2", "read"}, {"alice", "data2", "write"}})
}

func TestAdapter(t *testing.T) {
	connStr := os.Getenv("PG_CONN")
	require.NotEmpty(t, connStr, "must run with non-empty PG_CONN")
	defer dropDB(t, "test_pgxadapter")
	a, err := NewAdapter(connStr, WithDatabase("test_pgxadapter"), WithTableName("test_casbin_rules"))
	require.NoError(t, err)
	defer a.Close()

	e, err := casbin.NewEnforcer("testdata/rbac_model.conf", "testdata/rbac_policy.csv")
	require.NoError(t, err)

	type subtest struct {
		Name string
		F    func(t *testing.T, a *Adapter, e *casbin.Enforcer)
	}

	t.Run("", func(t *testing.T) {
		for _, st := range []subtest{
			{"SaveLoad", testSaveLoad},
			{"AutoSave", testAutoSave},
			{"RemovePolicy", testRemovePolicy},
			{"RemoveFilteredPolicy", testRemoveFilteredPolicy},
			{"RemoveFilteredGroupingPolicy", testRemoveFilteredGroupingPolicy},
			{"LoadFilteredPolicy", testLoadFilteredPolicy},
			{"LoadFilteredGroupingPolicy", testLoadFilteredGroupingPolicy},
			{"LoadFilteredPolicyNilFilter", testLoadFilteredPolicyNilFilter},
			{"SavePolicyClearPreviousData", testSavePolicyClearPreviousData},
			{"UpdatePolicy", testUpdatePolicy},
			{"UpdatePolicyWithLoadFilteredPolicy", testUpdatePolicyWithLoadFilteredPolicy},
			{"CustomDatabaseAndTableName", testCustomDatabaseAndTableName},
		} {
			st := st
			t.Run(st.Name, func(t *testing.T) {
				// This is a trick to save the current policy to the DB.
				// We can't call e.SavePolicy() because the adapter in the enforcer is still the file adapter.
				// The current policy means the policy in the Casbin enforcer (aka in memory).
				err = a.SavePolicy(e.GetModel())
				require.NoError(t, err)
				e2, err := casbin.NewEnforcer("testdata/rbac_model.conf", a)
				require.NoError(t, err)
				st.F(t, a, e2)
			})
		}
	})
}

func TestCustomSchema(t *testing.T) {
	connStr := os.Getenv("PG_CONN")
	require.NotEmpty(t, connStr, "must run with non-empty PG_CONN")
	defer dropDB(t, "test_pgxadapter")
	a, err := NewAdapter(connStr, WithDatabase("test_pgxadapter"), WithSchema("My_Schema"), WithTableName("TestCasbinRules"))
	require.NoError(t, err)
	defer a.Close()

	// save the policies
	e, err := casbin.NewEnforcer("testdata/rbac_model.conf", "testdata/rbac_policy.csv")
	require.NoError(t, err)
	require.NoError(t, a.SavePolicy(e.GetModel()))

	// reread the policies
	e2, err := casbin.NewEnforcer("testdata/rbac_model.conf", a)
	require.NoError(t, err)
	assert.False(t, e2.IsFiltered())
	res, err := e2.GetPolicy()
	require.NoError(t, err)
	assertPolicy(t,
		[][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}},
		res,
	)

	// nothing found in public schema
	a, err = NewAdapter(connStr, WithDatabase("test_pgxadapter"))
	require.NoError(t, err)
	defer a.Close()
	e3, err := casbin.NewEnforcer("testdata/rbac_model.conf", a)
	require.NoError(t, err)
	assert.False(t, e3.IsFiltered())
	res, err = e3.GetPolicy()
	require.NoError(t, err)
	assertPolicy(t,
		[][]string{},
		res,
	)
}

func TestRejectCollidingTableName(t *testing.T) {
	connStr := os.Getenv("PG_CONN")
	require.NotEmpty(t, connStr, "must run with non-empty PG_CONN")
	dbName := "test_pgxadapter"
	pool, err := createDatabase(dbName, connStr)
	require.NoError(t, err)
	defer dropDB(t, dbName)
	defer pool.Close()
	ctx := context.Background()
	_, err = pool.Exec(ctx, `
		CREATE TABLE test_casbin_rules (
			id text PRIMARY KEY,
			p_type text,
			v0 text,
			v1 text,
			v2 text,
			v3 text,
			v4 text,
			v5 text
		)
	`)
	require.NoError(t, err)

	_, err = NewAdapter(connStr, WithDatabase(dbName), WithTableName("Test_Casbin_Rules"))
	assert.Equal(t, fmt.Errorf("pgxadapter.NewAdapter: found table with similar name only in lower case: \"test_casbin_rules\". Either use this table name exactly, or choose a different name"), err)

	a, err := NewAdapter(connStr, WithDatabase(dbName), WithTableName("test_casbin_rules"))
	require.NoError(t, err)
	defer a.Close()
}
