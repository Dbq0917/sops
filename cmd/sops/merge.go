package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/cmd/sops/codes"
	"github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/keyservice"
)

type mergeOpts struct {
	Cipher          sops.Cipher
	InputStore      sops.Store
	OutputStore     sops.Store
	BasePath        string
	LocalPath       string
	RemotePath      string
	IgnoreMAC       bool
	KeyServices     []keyservice.KeyServiceClient
	DecryptionOrder []string
}

func merge(opts mergeOpts) ([]byte, []sops.MergeConflict, error) {
	localTree, err := decryptMergeInput(opts.LocalPath, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("could not decrypt local file: %w", err)
	}
	remoteTree, err := decryptMergeInput(opts.RemotePath, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("could not decrypt remote file: %w", err)
	}

	var baseBranches sops.TreeBranches
	if opts.BasePath != "" {
		empty, err := isEmptyFile(opts.BasePath)
		if err != nil {
			return nil, nil, fmt.Errorf("could not read base file: %w", err)
		}
		if !empty {
			baseTree, err := decryptMergeInput(opts.BasePath, opts)
			if err != nil {
				return nil, nil, fmt.Errorf("could not decrypt base file: %w", err)
			}
			baseBranches = baseTree.Branches
		}
	}

	mergedBranches, conflicts := sops.MergeBranches(baseBranches, localTree.Branches, remoteTree.Branches)
	if len(conflicts) > 0 {
		return nil, conflicts, nil
	}

	localTree.Branches = mergedBranches
	err = common.EncryptTree(common.EncryptTreeOpts{
		DataKey: localTree.Metadata.DataKey,
		Tree:    localTree,
		Cipher:  opts.Cipher,
	})
	if err != nil {
		return nil, nil, err
	}

	output, err := opts.OutputStore.EmitEncryptedFile(*localTree)
	if err != nil {
		return nil, nil, common.NewExitError(fmt.Sprintf("Could not marshal tree: %s", err), codes.ErrorDumpingTree)
	}
	return output, nil, nil
}

func decryptMergeInput(path string, opts mergeOpts) (*sops.Tree, error) {
	tree, err := common.LoadEncryptedFileWithBugFixes(common.GenericDecryptOpts{
		Cipher:      opts.Cipher,
		InputStore:  opts.InputStore,
		InputPath:   path,
		IgnoreMAC:   opts.IgnoreMAC,
		KeyServices: opts.KeyServices,
	})
	if err != nil {
		return nil, err
	}
	_, err = common.DecryptTree(common.DecryptTreeOpts{
		Cipher:          opts.Cipher,
		IgnoreMac:       opts.IgnoreMAC,
		Tree:            tree,
		KeyServices:     opts.KeyServices,
		DecryptionOrder: opts.DecryptionOrder,
	})
	if err != nil {
		return nil, err
	}
	return tree, nil
}

func isEmptyFile(path string) (bool, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return info.Size() == 0, nil
}

func conflictMessage(conflicts []sops.MergeConflict) string {
	paths := make([]string, 0, len(conflicts))
	for _, conflict := range conflicts {
		paths = append(paths, conflict.PathString())
	}
	return fmt.Sprintf(
		"encrypted file has conflicting changes at: %s\n"+
			"no output was written; resolve the values with `sops edit` and retry the merge",
		strings.Join(paths, ", "),
	)
}

func writeMergeOutput(path string, output []byte) error {
	if path == "" || path == "-" {
		_, err := os.Stdout.Write(output)
		return err
	}

	mode := os.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.WriteFile(path, output, mode)
}
