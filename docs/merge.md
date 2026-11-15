# Merging encrypted files

SOPS encrypts individual values but authenticates the whole document with a
file-level MAC. Two branches that both save the same encrypted file therefore
usually conflict on `lastmodified` and `mac`, even when they changed different
keys. Resolving that conflict by choosing one side's metadata makes the other
side's values fail authentication.

`sops merge` performs a three-way merge in plaintext:

1. Decrypts the common ancestor, local, and remote revisions and verifies each
   revision independently.
2. Merges the decrypted trees structurally.
3. Encrypts the merged tree once using the local revision's data key and
   metadata, producing a new MAC and `lastmodified` value.
4. Writes nothing if the same value changed differently on both sides. The
   command exits non-zero and reports only the conflicting key paths.

The encrypted file is never edited with conflict markers, so a successful
merge always produces a valid SOPS document that can be decrypted and verified.

## Configure Git

Add a merge driver to the repository:

```sh
git config merge.sops.name "SOPS encrypted file merge driver"
git config merge.sops.driver "sops merge --base %O --local %A --remote %B --output %A --filename-override %P"
```

Git passes `%O`, `%A`, and `%B` as temporary files without filename
extensions. `--filename-override %P` tells SOPS to use the real repository path
to select the YAML, JSON, dotenv, or INI parser.

Then mark the encrypted files in `.gitattributes`:

```gitattributes
*.enc.yaml merge=sops
*.enc.json merge=sops
*.enc.env merge=sops
*.enc.ini merge=sops
```

The driver is used for future merges only. Existing commits do not need to be
rewritten, amended, or filtered.

## Resolve an existing conflict

If Git already left stage entries for the file, the three revisions can be
extracted and merged without changing history:

```sh
git show :1:secrets.enc.yaml > /tmp/base.enc.yaml
git show :2:secrets.enc.yaml > /tmp/local.enc.yaml
git show :3:secrets.enc.yaml > /tmp/remote.enc.yaml
sops merge \
  --base /tmp/base.enc.yaml \
  --local /tmp/local.enc.yaml \
  --remote /tmp/remote.enc.yaml \
  --output secrets.enc.yaml
git add secrets.enc.yaml
```

To preview the result instead of writing the working-tree file, use
`--output -`.

## Conflicts

The merge is intentionally conservative. It fails without writing an output
file for:

- the same key changed to different values on both sides;
- one side deleting a key that the other side changed;
- incompatible array edits, such as different replacements at the same index.

Concurrent object additions are combined, and list appends from both sides are
combined in local-then-remote order. For a reported conflict, select one side
with `git checkout --ours` or `git checkout --theirs`, then use `sops edit` (or
`sops set`) to apply the intended value through SOPS so the MAC is regenerated.

The binary store encrypts the entire file as one value and cannot be merged
structurally. Store collaboratively edited secrets in YAML, JSON, dotenv, or
INI instead.
