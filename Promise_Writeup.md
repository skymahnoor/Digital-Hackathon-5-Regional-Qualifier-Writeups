# Writeup: Promise (250 pts, Crypto)

## Flag

```
crypto{r4t10s_0f_sh1ft3d_1nv3rs3s_c0nv3rg3_t0_th3_k3y1794649924AERpwOhC15cdc94487341537dd1f137d6f7c7f772f094e3b_133}
```

## What the challenge gives us

The challenge gives us a Python file called `chall.py`. This file builds a kind of encryption scheme that looks like a "knapsack" cipher (this family is called Naccache-Stern / CNS07). In simple words, here is what it does:

- It picks **150 small prime numbers**, each about 40-45 bits long. Call them `p_1, p_2, ..., p_150`.
- It picks one **big number `g`** (about 1803 bits long) and one **secret number `u`**.
- It builds a **public key**: for every prime `p_i`, it computes

  ```
  t_i = (p_i inverse mod g) - u   (mod g)
  ```

  This list of `t_i` values is given to everyone — this is the "public key" (`pk`).

- To encrypt a message, it picks 20 secret positions out of the 150, and puts a random 40-bit number `x_i` in each chosen position (everything else is 0). This list of 150 numbers (mostly zero, 20 of them not zero) is called `e`.
- The ciphertext is two numbers:
  - `c1 = sum of (x_i * t_i)` for all positions (no modulo, just a normal big sum)
  - `c2 = sum of x_i` (just adding up the 20 secret numbers)
- Then it builds a **key** using `sha256` from the secret `e` and the ciphertext, and finally:

  ```
  enc = FLAG XOR shake_256(key)
  ```

So to get the flag, we must find `e` (the 20 secret numbers), then build the same `key`, then XOR it with `enc` to get the flag back.

To find `e`, we first need to find the full secret key: the 150 primes `p_i`, the big number `g`, and the secret `u`.

## Step 1: Finding the weak point in the public key

By definition of `t_i`:

```
(t_i + u) * p_i = 1 + K_i * g
```

where `K_i` is some unknown whole number. If we divide both sides by `p_i * g`, we get:

```
(t_i + u) / g  is very close to  K_i / p_i
```

The error here is extremely tiny (about `2^-1848`). This means the fraction `(t_i + u)/g` is almost exactly equal to a simple fraction `K_i/p_i`, where the bottom number (`p_i`) is small — only about 45 bits. **This is the leak we will use.**

## Step 2: Getting rid of the unknown `u`

If we take the **difference** of two of these fractions, the secret `u` cancels out:

```
(t_i - t_j) / g  is close to  M_ij / (p_i * p_j)
```

Here `M_ij` is some number about 90 bits long. Now `u` is gone, and the bottom of the fraction only has `p_i * p_j` in it.

Next, we take the **ratio of two such differences**. This also makes the big number `g` cancel out, leaving only public numbers:

```
(t_a - t_i) / (t_a - t_b)  =  (M_ai * p_b) / (M_ab * p_i)
```

This is now a small fraction (about 135 bits on top and bottom), built only from public key values.

## Step 3: Using continued fractions to get the exact numbers

The left side of the equation above is a huge ~1800-bit ratio, but it is extremely close to a much smaller, exact fraction. We can find that exact fraction using a math tool called **continued fractions**. We expand the continued fraction step by step, and we stop as soon as one of the numbers in the expansion becomes very large (bigger than `2^250`). The fraction we have at that point is the true, small fraction we were looking for.

## Step 4: Recovering every prime number `p_i`

The bottom of the small fraction we just found contains `M_ab * p_i`. If we repeat this process for a few different values of `b` (we used 6 different ones) while keeping `a` and `i` fixed, we get several numbers that all contain `p_i` as a common factor. Taking the **greatest common divisor (GCD)** of these numbers gives us `p_i`, possibly with a few small extra factors mixed in. We remove any factors smaller than `2^16`.

Doing this for every position, we successfully recovered **all 150 primes**, and every single one was a true prime number inside the expected range.

(Small note: for the case where `a` equals `i`, we had to pick a different starting reference, so for `a = 0` we used `b0 = 1` instead.)

## Step 5: Recovering `g` and `u`

There is an exact relationship (no approximation needed):

```
(t_i - t_j) * p_i * p_j - (p_j - p_i) = g * M_ij
```

Since we now know all the primes, we can compute the left side for several pairs `(i, j)` and take the GCD of the results. This gives us `g` (the full 1803-bit number).

Once we know `g`, we can find `u` from just one equation:

```
u = (inverse of p_0 mod g) - t_0   (mod g)
```

We double-checked this by confirming that `(t_i + u) * p_i ≡ 1 (mod g)` is true for all 150 primes — and it was.

## Step 6: Decrypting the message

Now we have the full secret key: the primes, `g`, and `u`. We used the exact same `decrypt` logic that was already written in `chall.py`:

1. Compute `s = (c1 + u * c2) mod g`.
2. Use a method called "rational reconstruction" on `(g, s)` to get a fraction. The bottom part (`den`) of this fraction turns out to be the product of the primes at the 20 secret positions.
3. Find which primes divide `den` — these are exactly the 20 chosen positions.
4. Use the Chinese Remainder Theorem (CRT) to recover each secret value `x_i` at those positions.

We checked our answer two ways:
- There were exactly 20 non-zero values, as expected.
- `sum(e) == c2` was true, and `sum(x_i * t_i) == c1` was also true.

Both checks passed, so our recovered `e` was correct.

## Step 7: Getting the flag

With the correct `e` in hand, we just followed the same formula the challenge uses:

```
key  = sha256("1|" + str(e) + "|" + str(ciphertext))
flag = enc  XOR  shake_256(key)
```

This gave us the flag shown at the top of this writeup. The strange-looking part in the middle of the flag (`1794649924AERpw...`) is just a random part added by the server each time — we submit the whole string exactly as given.

## Takeaway (the simple lesson)

Even though the scheme tried to hide the primes behind a secret number `u`, that trick didn't fully work:

- Subtracting two public key values makes `u` disappear.
- Dividing two of those differences makes the big modulus `g` disappear too.

What's left behind is a small, simple fraction made only of the tiny prime numbers — and continued fractions are exactly the right tool to pull those small numbers back out of a fraction. This is why the scheme's own safety "promise" (that a certain product stays smaller than `g`) was not enough to protect it: the public key itself was already leaking the secret primes.
