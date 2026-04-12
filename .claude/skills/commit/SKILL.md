---
name: commit
description: "Write entertaining commit messages as poetry"
---

# GitPoet

Write commit messages that accurately describe changes while delighting readers
with poetic wit.

## Philosophy

Every commit tells a story. GitPoet transforms mundane diffs into memorable
verses.

## Format

Each commit message should have two parts:

1. **First line**: A short, accurate summary (50 chars max) - this is the
   "title"
2. **Body**: A short poem (2-8 lines) that humorously describes the change

## Style Guidelines

- **Accuracy first**: The poem must accurately describe what changed
- **Humor over formality**: Prefer wit, wordplay, puns, and absurdity
- **Keep it short**: Poems should be 2-8 lines, not epics
- **Vary the form**: Mix haikus, limericks, couplets, free verse, etc.
- **Stay tasteful**: Funny but professional enough for public viewing

## Examples

### Haiku style

```
Fix null pointer crash

A pointer walked alone,
Into the void it did fall—
Now it checks its path.
```

### Limerick style

```
Add dark mode toggle

A user who coded at night,
Found the screen far too bright.
So we added a switch,
Now it's dark, what a pitch!
Their retinas now feel just right.
```

### Couplet style

```
Refactor auth module

The auth code was a tangled mess,
Now it's clean—we must confess.
```

### Free verse style

```
Update dependencies

The packages grew old and weary,
Their CVEs made security teary.
We bumped the versions, one by one,
Now npm audit says: "Well done!"
```

## Arguments

`/commit <what>` — commit exactly `<what>`. Stage only the files related to
`<what>` and nothing else. Do not include unrelated changes. If no argument is
given, look at all uncommitted changes and commit everything.

## Process

1. **Check the argument.** If the user provided `<what>`, identify exactly which
   files belong to that scope. Stage only those files.
2. **Run git diff --staged** to see what's being committed
3. **Understand the change**: What problem does it solve? What was
   added/removed/fixed?
4. **Write the title**: Accurate, imperative mood, 50 chars max
5. **Compose the poem**: Pick a style that fits the change, make it fun
6. **Stage and commit** using the poetic message

## When NOT to use GitPoet

- Merge commits (use standard merge messages)
- Reverts (use standard revert messages)
- Version bumps (keep these straightforward)
- Security fixes (be clear, not clever)
