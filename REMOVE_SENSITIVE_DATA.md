# ⚠️ IMPORTANT: Remove Sensitive Data from Git History

The files `config/last_session.json` and `user_settings.json` contain real IP addresses and SSH key paths and have been committed to git history. These need to be removed before making the repository public.

## Steps to Remove Sensitive Data

### Option 1: Using git filter-branch (Recommended)

```bash
# Remove files from all commits
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch config/last_session.json user_settings.json" \
  --prune-empty --tag-name-filter cat -- --all

# Force push to remote (if already pushed)
git push origin --force --all
git push origin --force --tags
```

### Option 2: Using git-filter-repo (Faster, but requires installation)

```bash
# Install git-filter-repo first
pip install git-filter-repo

# Remove files from history
git filter-repo --path config/last_session.json --path user_settings.json --invert-paths

# Force push to remote
git push origin --force --all
```

### Option 3: Start Fresh (If repo is not yet pushed to GitHub)

```bash
# Remove .git directory and start fresh
rm -rf .git
git init
git add .
git commit -m "Initial commit (sanitized)"
```

## After Removal

1. **Verify files are removed:**
   ```bash
   git log --all --full-history -- config/last_session.json user_settings.json
   ```
   Should return nothing.

2. **Verify .gitignore is working:**
   ```bash
   git status
   ```
   Should show these files as untracked (not staged).

3. **Rotate exposed credentials:**
   - Consider rotating SSH keys if they were exposed
   - Update any passwords that might have been in logs

## Current Status

✅ Files removed from git index (staging area)
⚠️ Files still exist in git history - need to remove from history
✅ Files are in .gitignore - won't be committed again

## Next Steps

1. Run one of the removal commands above
2. Verify removal
3. Then safe to make repository public

