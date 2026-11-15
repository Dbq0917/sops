package sops

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func branch(items ...TreeItem) TreeBranch {
	return TreeBranch(items)
}

func item(key string, value interface{}) TreeItem {
	return TreeItem{Key: key, Value: value}
}

func branchValue(t *testing.T, branch TreeBranch, key string) interface{} {
	t.Helper()
	value, ok := findItem(branch, key)
	require.True(t, ok, "key %q not found", key)
	return value.Value
}

func TestMergeBranchesDisjointChanges(t *testing.T) {
	base := TreeBranches{branch(item("a", "base-a"), item("b", "base-b"), item("c", "base-c"))}
	local := TreeBranches{branch(item("a", "local-a"), item("b", "base-b"), item("c", "base-c"))}
	remote := TreeBranches{branch(item("a", "base-a"), item("b", "remote-b"), item("c", "base-c"))}

	merged, conflicts := MergeBranches(base, local, remote)

	require.Empty(t, conflicts)
	require.Len(t, merged, 1)
	assert.Equal(t, "local-a", branchValue(t, merged[0], "a"))
	assert.Equal(t, "remote-b", branchValue(t, merged[0], "b"))
	assert.Equal(t, "base-c", branchValue(t, merged[0], "c"))
}

func TestMergeBranchesAddsAndDeletesDistinctKeys(t *testing.T) {
	base := TreeBranches{branch(item("a", 1), item("removed", true))}
	local := TreeBranches{branch(item("a", 1), item("local-only", "local"))}
	remote := TreeBranches{branch(item("a", 1), item("removed", true), item("remote-only", "remote"))}

	merged, conflicts := MergeBranches(base, local, remote)

	require.Empty(t, conflicts)
	require.Len(t, merged, 1)
	assert.Equal(t, "local", branchValue(t, merged[0], "local-only"))
	assert.Equal(t, "remote", branchValue(t, merged[0], "remote-only"))
	_, removed := findItem(merged[0], "removed")
	assert.False(t, removed)
}

func TestMergeBranchesNestedBranches(t *testing.T) {
	base := TreeBranches{branch(
		item("database", branch(item("host", "db"), item("port", 5432))),
		item("name", "app"),
	)}
	local := TreeBranches{branch(
		item("database", branch(item("host", "db.internal"), item("port", 5432))),
		item("name", "app"),
	)}
	remote := TreeBranches{branch(
		item("database", branch(item("host", "db"), item("port", 5433))),
		item("name", "app"),
	)}

	merged, conflicts := MergeBranches(base, local, remote)

	require.Empty(t, conflicts)
	database := branchValue(t, merged[0], "database").(TreeBranch)
	assert.Equal(t, "db.internal", branchValue(t, database, "host"))
	assert.Equal(t, 5433, branchValue(t, database, "port"))
}

func TestMergeBranchesArrayChanges(t *testing.T) {
	base := TreeBranches{branch(item("hosts", []interface{}{"a", "b", "c"}))}
	local := TreeBranches{branch(item("hosts", []interface{}{"a", "local", "c"}))}
	remote := TreeBranches{branch(item("hosts", []interface{}{"a", "b", "remote"}))}

	merged, conflicts := MergeBranches(base, local, remote)

	require.Empty(t, conflicts)
	assert.Equal(t, []interface{}{"a", "local", "remote"}, branchValue(t, merged[0], "hosts"))
}

func TestMergeBranchesConcurrentAppends(t *testing.T) {
	base := TreeBranches{branch(item("hosts", []interface{}{"a"}))}
	local := TreeBranches{branch(item("hosts", []interface{}{"a", "b"}))}
	remote := TreeBranches{branch(item("hosts", []interface{}{"a", "c"}))}

	merged, conflicts := MergeBranches(base, local, remote)

	require.Empty(t, conflicts)
	assert.Equal(t, []interface{}{"a", "b", "c"}, branchValue(t, merged[0], "hosts"))
}

func TestMergeBranchesSameKeyConflict(t *testing.T) {
	base := TreeBranches{branch(item("password", "old"))}
	local := TreeBranches{branch(item("password", "local"))}
	remote := TreeBranches{branch(item("password", "remote"))}

	_, conflicts := MergeBranches(base, local, remote)

	require.Len(t, conflicts, 1)
	assert.Equal(t, "password", conflicts[0].PathString())
}

func TestMergeBranchesDeleteModifyConflict(t *testing.T) {
	base := TreeBranches{branch(item("password", "old"))}
	local := TreeBranches{branch()}
	remote := TreeBranches{branch(item("password", "remote"))}

	_, conflicts := MergeBranches(base, local, remote)

	require.Len(t, conflicts, 1)
	assert.Equal(t, "password", conflicts[0].PathString())
}

func TestMergeBranchesAddAdd(t *testing.T) {
	local := TreeBranches{branch(item("local", 1), item("shared", "local"))}
	remote := TreeBranches{branch(item("remote", 2), item("shared", "remote"))}

	merged, conflicts := MergeBranches(nil, local, remote)

	require.Len(t, conflicts, 1)
	assert.Equal(t, "shared", conflicts[0].PathString())
	require.Len(t, merged, 1)
	assert.Equal(t, 1, branchValue(t, merged[0], "local"))
	assert.Equal(t, 2, branchValue(t, merged[0], "remote"))
}
