package sops

import (
	"fmt"
	"strings"
)

// MergeConflict describes a path that could not be merged automatically.
// The value fields are available for programmatic inspection; PathString is
// safe to show to users because it never contains values.
type MergeConflict struct {
	Path         []interface{}
	Base         interface{}
	Local        interface{}
	Remote       interface{}
	BaseExists   bool
	LocalExists  bool
	RemoteExists bool
}

// PathString returns a human-readable representation of the conflicting path.
func (c MergeConflict) PathString() string {
	if len(c.Path) == 0 {
		return "<document>"
	}
	var b strings.Builder
	for _, component := range c.Path {
		switch component := component.(type) {
		case string:
			if b.Len() > 0 {
				b.WriteByte('.')
			}
			b.WriteString(component)
		case int:
			fmt.Fprintf(&b, "[%d]", component)
		default:
			if b.Len() > 0 {
				b.WriteByte('.')
			}
			fmt.Fprintf(&b, "%v", component)
		}
	}
	return b.String()
}

type optionalValue struct {
	value  interface{}
	exists bool
}

func optional(value interface{}, exists bool) optionalValue {
	return optionalValue{value: value, exists: exists}
}

func optionalEqual(a, b optionalValue) bool {
	if a.exists != b.exists {
		return false
	}
	if !a.exists {
		return true
	}
	return equals(a.value, b.value)
}

// MergeBranches performs a three-way structural merge of decrypted SOPS data
// branches. It does not merge SOPS metadata such as master keys or MACs; those
// belong to the encrypted document that is written after the merge.
//
// The merge is deliberately conservative: if both sides changed the same value
// differently, or if one side deleted a value that the other side changed, the
// path is reported as a conflict and no value is guessed.
func MergeBranches(base, local, remote TreeBranches) (TreeBranches, []MergeConflict) {
	switch {
	case branchesEqual(local, remote):
		return cloneBranches(local), nil
	case branchesEqual(base, local):
		return cloneBranches(remote), nil
	case branchesEqual(base, remote):
		return cloneBranches(local), nil
	}

	var merged TreeBranches
	var conflicts []MergeConflict
	switch {
	case len(base) == 0 && len(local) == len(remote):
		for i := range local {
			branch, branchConflicts := mergeBranch(nil, local[i], remote[i], documentPath(i, len(local)))
			merged = append(merged, branch)
			conflicts = append(conflicts, branchConflicts...)
		}
	case len(base) == len(local) && len(local) == len(remote):
		for i := range base {
			branch, branchConflicts := mergeBranch(base[i], local[i], remote[i], documentPath(i, len(base)))
			merged = append(merged, branch)
			conflicts = append(conflicts, branchConflicts...)
		}
	default:
		conflicts = append(conflicts, MergeConflict{
			Base:         base,
			Local:        local,
			Remote:       remote,
			BaseExists:   base != nil,
			LocalExists:  local != nil,
			RemoteExists: remote != nil,
		})
	}
	return merged, conflicts
}

func documentPath(index, count int) []interface{} {
	if count <= 1 {
		return nil
	}
	return []interface{}{index}
}

func branchesEqual(a, b TreeBranches) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !equals(a[i], b[i]) {
			return false
		}
	}
	return true
}

func cloneBranches(branches TreeBranches) TreeBranches {
	cloned := make(TreeBranches, len(branches))
	copy(cloned, branches)
	return cloned
}

func mergeBranch(base, local, remote TreeBranch, path []interface{}) (TreeBranch, []MergeConflict) {
	var merged TreeBranch
	var conflicts []MergeConflict
	for _, key := range branchKeys(base, local, remote) {
		baseItem, baseOK := findItem(base, key)
		localItem, localOK := findItem(local, key)
		remoteItem, remoteOK := findItem(remote, key)

		value, exists, valueConflicts := mergeValue(
			optional(baseItem.Value, baseOK),
			optional(localItem.Value, localOK),
			optional(remoteItem.Value, remoteOK),
			appendPath(path, key),
		)
		conflicts = append(conflicts, valueConflicts...)
		if !exists {
			continue
		}

		mergedKey := key
		switch {
		case localOK:
			mergedKey = localItem.Key
		case remoteOK:
			mergedKey = remoteItem.Key
		case baseOK:
			mergedKey = baseItem.Key
		}
		merged = append(merged, TreeItem{Key: mergedKey, Value: value})
	}
	return merged, conflicts
}

func branchKeys(base, local, remote TreeBranch) []interface{} {
	keys := make([]interface{}, 0, len(base)+len(local)+len(remote))
	seen := func(key interface{}) bool {
		for _, existing := range keys {
			if equals(existing, key) {
				return true
			}
		}
		return false
	}
	add := func(branch TreeBranch) {
		for _, item := range branch {
			if !seen(item.Key) {
				keys = append(keys, item.Key)
			}
		}
	}
	add(base)
	add(local)
	add(remote)
	return keys
}

func findItem(branch TreeBranch, key interface{}) (TreeItem, bool) {
	for _, item := range branch {
		if equals(item.Key, key) {
			return item, true
		}
	}
	return TreeItem{}, false
}

func appendPath(path []interface{}, component interface{}) []interface{} {
	newPath := make([]interface{}, len(path)+1)
	copy(newPath, path)
	newPath[len(path)] = component
	return newPath
}

func mergeValue(base, local, remote optionalValue, path []interface{}) (interface{}, bool, []MergeConflict) {
	switch {
	case optionalEqual(local, remote):
		return local.value, local.exists, nil
	case optionalEqual(base, local):
		return remote.value, remote.exists, nil
	case optionalEqual(base, remote):
		return local.value, local.exists, nil
	}

	if !base.exists && local.exists && remote.exists {
		switch localValue := local.value.(type) {
		case TreeBranch:
			if remoteValue, ok := remote.value.(TreeBranch); ok {
				merged, conflicts := mergeBranch(nil, localValue, remoteValue, path)
				return merged, true, conflicts
			}
		case []interface{}:
			if remoteValue, ok := remote.value.([]interface{}); ok {
				merged, conflicts := mergeSlice(nil, localValue, remoteValue, path)
				return merged, true, conflicts
			}
		}
	}

	if base.exists && local.exists && remote.exists {
		switch baseValue := base.value.(type) {
		case TreeBranch:
			localValue, localOK := local.value.(TreeBranch)
			remoteValue, remoteOK := remote.value.(TreeBranch)
			if localOK && remoteOK {
				merged, conflicts := mergeBranch(baseValue, localValue, remoteValue, path)
				return merged, true, conflicts
			}
		case []interface{}:
			localValue, localOK := local.value.([]interface{})
			remoteValue, remoteOK := remote.value.([]interface{})
			if localOK && remoteOK {
				merged, conflicts := mergeSlice(baseValue, localValue, remoteValue, path)
				return merged, true, conflicts
			}
		}
	}

	return nil, false, []MergeConflict{{
		Path:         path,
		Base:         base.value,
		Local:        local.value,
		Remote:       remote.value,
		BaseExists:   base.exists,
		LocalExists:  local.exists,
		RemoteExists: remote.exists,
	}}
}

func mergeSlice(base, local, remote []interface{}, path []interface{}) ([]interface{}, []MergeConflict) {
	if len(base) == len(local) && len(local) == len(remote) {
		merged := make([]interface{}, len(base))
		var conflicts []MergeConflict
		for i := range base {
			value, exists, valueConflicts := mergeValue(
				optional(base[i], true),
				optional(local[i], true),
				optional(remote[i], true),
				appendPath(path, i),
			)
			conflicts = append(conflicts, valueConflicts...)
			if exists {
				merged[i] = value
			}
		}
		return merged, conflicts
	}

	// Concurrent appends are common for lists of recipients or hosts. Merge
	// them deterministically, while rejecting edits to the common prefix.
	if len(local) >= len(base) && len(remote) >= len(base) &&
		sliceEqual(base, local[:len(base)]) && sliceEqual(base, remote[:len(base)]) {
		merged := append([]interface{}{}, base...)
		localExtras := local[len(base):]
		remoteExtras := remote[len(base):]
		merged = append(merged, localExtras...)
		if !sliceEqual(localExtras, remoteExtras) {
			merged = append(merged, remoteExtras...)
		}
		return merged, nil
	}

	return nil, []MergeConflict{{
		Path:         path,
		Base:         base,
		Local:        local,
		Remote:       remote,
		BaseExists:   true,
		LocalExists:  true,
		RemoteExists: true,
	}}
}

func sliceEqual(a, b []interface{}) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !equals(a[i], b[i]) {
			return false
		}
	}
	return true
}
