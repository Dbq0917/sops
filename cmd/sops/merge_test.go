package main

import (
	"os"
	"path/filepath"
	"testing"

	filipage "filippo.io/age"
	sopsage "github.com/getsops/sops/v3/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/stores/yaml"
	"github.com/getsops/sops/v3/version"
)

func testMergeStore() *yaml.Store {
	storesConfig := config.NewStoresConfig()
	return yaml.NewStore(&storesConfig.YAML)
}

func writeEncryptedTree(t *testing.T, path string, store *yaml.Store, tree *sops.Tree, dataKey []byte) {
	t.Helper()
	require.NoError(t, common.EncryptTree(common.EncryptTreeOpts{
		DataKey: dataKey,
		Tree:    tree,
		Cipher:  aes.NewCipher(),
	}))
	encrypted, err := store.EmitEncryptedFile(*tree)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, encrypted, 0o600))
}

func loadEncryptedTree(t *testing.T, path string, store *yaml.Store) *sops.Tree {
	t.Helper()
	tree, err := decryptTree(decryptOpts{
		Cipher:      aes.NewCipher(),
		InputStore:  store,
		OutputStore: store,
		InputPath:   path,
		KeyServices: []keyservice.KeyServiceClient{keyservice.NewLocalClient()},
	})
	require.NoError(t, err)
	return tree
}

func TestMergeEncryptedFilesKeepsAllValuesDecryptable(t *testing.T) {
	identity, err := filipage.GenerateX25519Identity()
	require.NoError(t, err)
	t.Setenv(sopsage.SopsAgeKeyEnv, identity.String())

	store := testMergeStore()
	recipient := identity.Recipient().String()
	masterKey, err := sopsage.MasterKeyFromRecipient(recipient)
	require.NoError(t, err)

	plaintext := []byte(`
db:
    host: db.example.com
    port: 5432
app:
    name: example
`)
	baseBranches, err := store.LoadPlainFile(plaintext)
	require.NoError(t, err)
	baseTree := &sops.Tree{
		Branches: baseBranches,
		Metadata: sops.Metadata{
			KeyGroups: []sops.KeyGroup{{masterKey}},
			Version:   version.Version,
		},
	}
	dataKey, errs := baseTree.GenerateDataKeyWithKeyServices([]keyservice.KeyServiceClient{keyservice.NewLocalClient()})
	require.Empty(t, errs)

	dir := t.TempDir()
	basePath := filepath.Join(dir, "secrets.yaml")
	localPath := filepath.Join(dir, "local.yaml")
	remotePath := filepath.Join(dir, "remote.yaml")
	outputPath := filepath.Join(dir, "merged.yaml")
	writeEncryptedTree(t, basePath, store, baseTree, dataKey)

	baseTree = loadEncryptedTree(t, basePath, store)
	baseTree.Branches[0], _ = baseTree.Branches[0].Set([]interface{}{"db", "host"}, "db.internal")
	writeEncryptedTree(t, localPath, store, baseTree, baseTree.Metadata.DataKey)

	baseTree = loadEncryptedTree(t, basePath, store)
	baseTree.Branches[0], _ = baseTree.Branches[0].Set([]interface{}{"db", "port"}, 5433)
	remoteKey, err := sopsage.MasterKeyFromRecipient(recipient)
	require.NoError(t, err)
	baseTree.Metadata.KeyGroups = []sops.KeyGroup{{remoteKey}}
	baseTree.Metadata.DataKey = nil
	remoteDataKey, remoteErrs := baseTree.GenerateDataKeyWithKeyServices([]keyservice.KeyServiceClient{keyservice.NewLocalClient()})
	require.Empty(t, remoteErrs)
	writeEncryptedTree(t, remotePath, store, baseTree, remoteDataKey)

	merged, conflicts, err := merge(mergeOpts{
		Cipher:          aes.NewCipher(),
		InputStore:      store,
		OutputStore:     store,
		BasePath:        basePath,
		LocalPath:       localPath,
		RemotePath:      remotePath,
		KeyServices:     []keyservice.KeyServiceClient{keyservice.NewLocalClient()},
		DecryptionOrder: sops.DefaultDecryptionOrder,
	})
	require.NoError(t, err)
	require.Empty(t, conflicts)
	require.NoError(t, os.WriteFile(outputPath, merged, 0o600))

	mergedTree := loadEncryptedTree(t, outputPath, store)
	db, err := mergedTree.Branches[0].Truncate([]interface{}{"db"})
	require.NoError(t, err)
	dbBranch := db.(sops.TreeBranch)
	hostValue, err := dbBranch.Truncate([]interface{}{"host"})
	require.NoError(t, err)
	portValue, err := dbBranch.Truncate([]interface{}{"port"})
	require.NoError(t, err)
	assert.Equal(t, "db.internal", hostValue)
	assert.Equal(t, 5433, portValue)
	assert.Equal(t, "example", mustTruncate(t, mergedTree.Branches[0], []interface{}{"app", "name"}))
}

func TestMergeEncryptedFilesReportsValueConflict(t *testing.T) {
	identity, err := filipage.GenerateX25519Identity()
	require.NoError(t, err)
	t.Setenv(sopsage.SopsAgeKeyEnv, identity.String())

	store := testMergeStore()
	masterKey, err := sopsage.MasterKeyFromRecipient(identity.Recipient().String())
	require.NoError(t, err)

	baseBranches, err := store.LoadPlainFile([]byte("password: old\n"))
	require.NoError(t, err)
	baseTree := &sops.Tree{
		Branches: baseBranches,
		Metadata: sops.Metadata{
			KeyGroups: []sops.KeyGroup{{masterKey}},
			Version:   version.Version,
		},
	}
	dataKey, errs := baseTree.GenerateDataKeyWithKeyServices([]keyservice.KeyServiceClient{keyservice.NewLocalClient()})
	require.Empty(t, errs)

	dir := t.TempDir()
	basePath := filepath.Join(dir, "secrets.yaml")
	localPath := filepath.Join(dir, "local.yaml")
	remotePath := filepath.Join(dir, "remote.yaml")
	writeEncryptedTree(t, basePath, store, baseTree, dataKey)

	baseTree = loadEncryptedTree(t, basePath, store)
	baseTree.Branches[0], _ = baseTree.Branches[0].Set([]interface{}{"password"}, "local")
	writeEncryptedTree(t, localPath, store, baseTree, baseTree.Metadata.DataKey)

	baseTree = loadEncryptedTree(t, basePath, store)
	baseTree.Branches[0], _ = baseTree.Branches[0].Set([]interface{}{"password"}, "remote")
	writeEncryptedTree(t, remotePath, store, baseTree, baseTree.Metadata.DataKey)

	output, conflicts, err := merge(mergeOpts{
		Cipher:          aes.NewCipher(),
		InputStore:      store,
		OutputStore:     store,
		BasePath:        basePath,
		LocalPath:       localPath,
		RemotePath:      remotePath,
		KeyServices:     []keyservice.KeyServiceClient{keyservice.NewLocalClient()},
		DecryptionOrder: sops.DefaultDecryptionOrder,
	})
	require.NoError(t, err)
	assert.Nil(t, output)
	require.Len(t, conflicts, 1)
	assert.Equal(t, "password", conflicts[0].PathString())
}

func mustTruncate(t *testing.T, branch sops.TreeBranch, path []interface{}) interface{} {
	t.Helper()
	value, err := branch.Truncate(path)
	require.NoError(t, err)
	return value
}
