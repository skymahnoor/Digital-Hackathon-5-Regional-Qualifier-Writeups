# Writeup: Helios Vault (50 pts, Crypto)

## Flag

```
prg{th3_qu0rum_h0lds_[A-Za-z0-9]{81794656116H6dyqP7y80b8009b6f305ce21759f69cc8a56e3b5c506e7b_133}
```

## What the challenge gives us

This is a **Shamir's Secret Sharing** challenge. In simple words, a secret number is hidden inside a polynomial (a math formula), and the secret is split into many "shares". You need enough shares (called the **threshold**) to get the secret back.

When we connect to the server:

1. It first sends one intro line in JSON format.
2. Then it runs **50 rounds**.
3. In every round it gives us:
   - a fresh **prime number** `p`,
   - a **threshold** value,
   - a list of points `[x, share]` that lie on a polynomial of degree `threshold - 1`.
4. We must send back the value of the polynomial at `x = 0`. This is the **secret**, calculated modulo the prime `p`.

Each round has only a **20 second** time limit, so we must solve it with a script (automation). Doing it by hand is not possible.

## Step 1: Understanding the math

If we have enough points, there is exactly **one** polynomial that passes through all of them. But we do not need to build the whole polynomial. We only need its value at `x = 0`, and **Lagrange interpolation** gives that directly:

```
f(0) = sum over i of:  y_i * product over j != i of: (-x_j) / (x_i - x_j)     (mod p)
```

Division is not normal in modular math, so we use a **modular inverse** instead. In Python this is `pow(den, -1, p)`. Because `p` is prime, the inverse always exists.

## Step 2: The automation script

```python
import socket, json, sys

def lagrange0(shares, p):
    s = 0
    for i, (xi, yi) in enumerate(shares):
        num, den = 1, 1
        for j, (xj, _) in enumerate(shares):
            if i != j:
                num = num * (-xj) % p
                den = den * (xi - xj) % p
        s = (s + yi * num * pow(den, -1, p)) % p
    return s

host, port = sys.argv[1], int(sys.argv[2])
sock = socket.create_connection((host, port))
f = sock.makefile("rw", newline="\n")
for line in f:
    line = line.strip()
    if not line:
        continue
    d = json.loads(line)
    if "round" in d and "shares" in d:
        sec = lagrange0(d["shares"], d["prime"])
        f.write(json.dumps({"secret": sec}) + "\n")
        f.flush()
    else:
        print(line)
```

What the script does:

- It connects to the server and reads one line at a time.
- If the line is a round (it has `round` and `shares`), it calculates the secret with `lagrange0` and sends it back as JSON.
- Any other line (like the intro or the final message) is just printed.

How to run it:

```
python3 helios.py 52.146.88.61 <port>
```

## Step 3: Result

The script solved all **50 rounds** correctly and the server replied:

```json
{"status": "unsealed", "rounds": 50, "flag": "prg{th3_qu0rum_h0lds_[A-Za-z0-9]{81794656116H6dyqP7y80b8009b6f305ce21759f69cc8a56e3b5c506e7b_133}"}
```

## Note about the strange flag

The flag looks odd. It contains regex-like text (`[A-Za-z0-9]{8}`), a timestamp and a hash. Many people may think it is a mistake in the challenge template. But the **full string exactly as the server gave it** is the real flag. We submitted it without changing or trimming anything and it was marked **Correct**.

## Takeaway (the simple lesson)

- The crypto part was standard: Shamir's Secret Sharing can be solved directly with Lagrange interpolation.
- The only "trick" was the confusing flag format. Always submit the flag exactly as the server gives it.
- When a challenge has a strict time limit per round, write a script to automate it.
