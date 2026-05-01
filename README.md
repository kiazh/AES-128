# AES-128 in Go

A from-scratch implementation of the Advanced Encryption Standard (AES) with a 128-bit key, written in pure Go. No external libraries. Passes the FIPS 197 test vector.

```
Plaintext  3243f6a8885a308d313198a2e0370734
Key        2b7e151628aed2a6abf7158809cf4f3c
Ciphertext 3925841d02dc09fbdc118597196a0b32  ✓
```

---

## Table of Contents

1. [Background](#background)
2. [The Math: GF(2⁸)](#the-math-gf28)
3. [S-Box](#s-box)
4. [The Four Round Operations](#the-four-round-operations)
   * [SubBytes](#subbytes)
   * [ShiftRows](#shiftrows)
   * [MixColumns](#mixcolumns)
   * [AddRoundKey](#addroundkey)
5. [Key Expansion](#key-expansion)
6. [Encryption and Decryption](#encryption-and-decryption)
7. [Usage](#usage)
8. [What's Implemented vs. Hardcoded](#whats-implemented-vs-hardcoded)
9. [Security Notes](#security-notes)

---

## Background

AES is a symmetric block cipher standardised by NIST in 2001 (FIPS 197). It operates on 128-bit (16-byte) blocks and supports key sizes of 128, 192, or 256 bits. This implementation uses a 128-bit key, which gives 10 rounds of processing.

The cipher was designed by Joan Daemen and Vincent Rijmen and was originally called **Rijndael**. Its security rests on three mathematical properties:

| Property | Achieved by |
| --- | --- |
| **Confusion** — each ciphertext bit depends on many key bits | SubBytes (S-box) |
| **Diffusion** — changing one plaintext bit changes ~half the ciphertext | ShiftRows + MixColumns |
| **Key mixing** — the key is blended into every round | AddRoundKey |

The block is treated as a **4×4 matrix of bytes**, called the *state*:

```
state[row][col]  ←  block[col*4 + row]   (column-major)

block:  b0  b1  b2  b3  b4  b5  b6  b7  b8  b9  b10 b11 b12 b13 b14 b15

state:  b0  b4  b8  b12
        b1  b5  b9  b13
        b2  b6  b10 b14
        b3  b7  b11 b15
```

---

## The Math: GF(2⁸)

Nearly everything in AES is arithmetic inside the **Galois field GF(2⁸)** — the finite field with 256 elements. This implementation actually computes in this field at runtime via the `gmul` function below.

### What is GF(2⁸)?

Elements are 8-bit bytes, interpreted as degree-7 polynomials over GF(2):

```
byte 0xb3 = 10110011₂
           = x⁷ + x⁵ + x⁴ + x + 1
```

Coefficients are in GF(2), so they can only be 0 or 1, and coefficient arithmetic is mod 2 (i.e., XOR).

### Addition

Addition in GF(2⁸) = bitwise XOR. No carries.

```
0x53 ⊕ 0xCA = 0x99

  01010011
⊕ 11001010
─────────
  10011001
```

### Multiplication

Multiplication is polynomial multiplication followed by reduction modulo the **AES irreducible polynomial**:

```
p(x) = x⁸ + x⁴ + x³ + x + 1  =  0x11b
```

This polynomial is irreducible over GF(2) — it cannot be factored — which makes the field well-defined and every nonzero element invertible.

**Example: 0x57 × 0x83**

```
0x57 = x⁶ + x⁴ + x² + x + 1
0x83 = x⁷ + x + 1

product (before reduction) = x¹³ + x¹¹ + x⁹ + x⁸ + x⁷ + x⁷ + x⁵ + x³ + x² + x⁶ + x⁴ + x² + x + x + x⁶ + x⁴ + x² + x + 1
                            = x¹³ + x¹¹ + x⁹ + x⁸ + x⁵ + x⁴ + x³ + x² + 1   (mod 2 coefficient reduction)

reduce mod x⁸+x⁴+x³+x+1:   0xc1
```

### The `gmul` Function

The implementation uses the **Russian Peasant** (double-and-add) algorithm — no log/antilog lookup tables:

```go
func gmul(a, b byte) byte {
    var p byte
    for i := 0; i < 8; i++ {
        if b&0x01 != 0 {
            p ^= a              // add a to product if LSB of b is set
        }
        hiBit := a & 0x80
        a <<= 1                 // double a (multiply by x)
        if hiBit != 0 {
            a ^= 0x1b           // reduce: subtract p(x) (lower 8 bits of 0x11b)
        }
        b >>= 1
    }
    return p
}
```

The `0x1b` reduction: when doubling `a` would overflow 8 bits (high bit set before shift), the result is reduced by XORing with `0x1b`. This is because `x⁸ ≡ x⁴ + x³ + x + 1 = 0x1b` modulo `p(x)`.

### Why a Finite Field?

Every nonzero element in GF(2⁸) has a multiplicative inverse. This makes the S-box bijective (reversible) and ensures MixColumns is invertible — both required for decryption.

---

## S-Box

The S-box is a 256-entry substitution table: `sBox[byte_in] = byte_out`.

> **Implementation note.** This project embeds the standard FIPS-197 S-box as a 256-byte literal in `aes.go` rather than generating it at startup. The construction below is the mathematical *definition* the table satisfies — it is the spec, not the runtime path. Computing the table from first principles is a planned future change (see [What's Implemented vs. Hardcoded](#whats-implemented-vs-hardcoded)).

The table satisfies a two-step definition for every input byte:

### Step 1 — Multiplicative Inverse in GF(2⁸)

For input byte `b`, take `b⁻¹` in GF(2⁸) such that `b · b⁻¹ = 1`. The special case `0⁻¹ = 0` is defined by convention.

This is the source of the S-box's **nonlinearity**. The map `b → b⁻¹` is highly nonlinear and defeats algebraic attacks.

### Step 2 — Affine Transform over GF(2)

Treat `b⁻¹` as 8 bits `[b₇ b₆ b₅ b₄ b₃ b₂ b₁ b₀]` and compute:

```
s_i = b_i ⊕ b_{(i+4) mod 8} ⊕ b_{(i+5) mod 8} ⊕ b_{(i+6) mod 8} ⊕ b_{(i+7) mod 8} ⊕ c_i
```

where `c = 0x63 = 01100011₂`. In matrix form:

```
⎡s₀⎤   ⎡1 0 0 0 1 1 1 1⎤ ⎡b₀⎤   ⎡1⎤
⎢s₁⎥   ⎢1 1 0 0 0 1 1 1⎥ ⎢b₁⎥   ⎢1⎥
⎢s₂⎥   ⎢1 1 1 0 0 0 1 1⎥ ⎢b₂⎥   ⎢0⎥
⎢s₃⎥ = ⎢1 1 1 1 0 0 0 1⎥ ⎢b₃⎥ ⊕ ⎢0⎥
⎢s₄⎥   ⎢1 1 1 1 1 0 0 0⎥ ⎢b₄⎥   ⎢0⎥
⎢s₅⎥   ⎢0 1 1 1 1 1 0 0⎥ ⎢b₅⎥   ⎢1⎥
⎢s₆⎥   ⎢0 0 1 1 1 1 1 0⎥ ⎢b₆⎥   ⎢1⎥
⎣s₇⎦   ⎣0 0 0 1 1 1 1 1⎦ ⎣b₇⎦   ⎣0⎦
```

The constant `0x63` ensures that no byte maps to itself (`sBox[x] ≠ x`) and no byte maps to its complement.

### Inverse S-Box

The inverse table *is* derived at runtime — by inverting the forward S-box mapping rather than by re-applying the inverse affine transform plus inverse:

```go
func buildInvSBox() [256]byte {
    var inv [256]byte
    for i := 0; i < 256; i++ {
        inv[sBox[i]] = byte(i)
    }
    return inv
}
```

This is a single O(256) pass at program initialization.

---

## The Four Round Operations

### SubBytes

Every byte of the state is independently replaced by its S-box value.

```
state[r][c] = sBox[state[r][c]]
```

**Purpose:** nonlinearity — breaks any algebraic relationship between plaintext and ciphertext that an attacker could exploit.

### ShiftRows

Row `r` is cyclically shifted left by `r` positions:

```
Row 0: unchanged       [a b c d] → [a b c d]
Row 1: left-shift 1    [e f g h] → [f g h e]
Row 2: left-shift 2    [i j k l] → [k l i j]
Row 3: left-shift 3    [m n o p] → [p m n o]
```

**Purpose:** ensures that after MixColumns, bytes from every column of the original state contribute to every column of the output. Without ShiftRows, MixColumns would operate on each column independently with no cross-column diffusion.

**Inverse (InvShiftRows):** shift right by the same amounts.

```go
// Row 1 inverse: right-shift 1 = left-shift 3
out[1][0], out[1][1], out[1][2], out[1][3] =
    s[1][3], s[1][0], s[1][1], s[1][2]
```

### MixColumns

Each column `[s₀, s₁, s₂, s₃]ᵀ` is treated as a polynomial over GF(2⁸) and multiplied by a fixed polynomial `a(x) = {03}x³ + {01}x² + {01}x + {02}` modulo `x⁴ + 1`. This is equivalent to the matrix multiplication:

```
⎡s'₀⎤   ⎡2 3 1 1⎤ ⎡s₀⎤
⎢s'₁⎥ = ⎢1 2 3 1⎥ ⎢s₁⎥   (all arithmetic in GF(2⁸))
⎢s'₂⎥   ⎢1 1 2 3⎥ ⎢s₂⎥
⎣s'₃⎦   ⎣3 1 1 2⎦ ⎣s₃⎦
```

So each output byte is a sum of GF(2⁸) products — for example:

```
s'₀ = gmul(2, s₀) ⊕ gmul(3, s₁) ⊕ s₂ ⊕ s₃
```

Note: `gmul(1, x) = x` (identity), `gmul(2, x) = xtime(x)` (one left-shift with conditional reduction), `gmul(3, x) = gmul(2,x) ⊕ x`.

**Purpose:** provides diffusion — every output byte of a column depends on all four input bytes. Combined with ShiftRows, after 2 rounds every output byte depends on every input byte (the AES *wide trail strategy*).

**Inverse (InvMixColumns):** multiply by the inverse matrix:

```
⎡14 11 13  9⎤
⎢ 9 14 11 13⎥
⎢13  9 14 11⎥
⎣11 13  9 14⎦
```

These coefficients are the multiplicative inverses of {2,3,1,1,...} in GF(2⁸) via Cramer's rule over the field. For example: `gmul(14, s₀) ⊕ gmul(11, s₁) ⊕ gmul(13, s₂) ⊕ gmul(9, s₃)`.

### AddRoundKey

XOR every byte of the state with the corresponding byte of the round key:

```
state[r][c] ^= roundKey[r][c]
```

**Purpose:** mixes the secret key into the data. This is the only step where the key enters. XOR is used because it is its own inverse (`a ⊕ k ⊕ k = a`), making decryption straightforward. It is also linear — its security comes entirely from the secrecy of the key and the nonlinearity of the surrounding S-box operations.

---

## Key Expansion

The 128-bit key is expanded into **11 round keys** (one for each of 10 rounds plus the initial whitening key), giving 44 words of 4 bytes each.

### Word Schedule

Words `w[0..3]` are the key itself. For `i = 4..43`:

```
if i mod 4 == 0:
    temp = SubWord(RotWord(w[i-1])) ⊕ Rcon[i/4 - 1]
else:
    temp = w[i-1]

w[i] = w[i-4] ⊕ temp
```

**RotWord:** rotate word left by one byte: `[a,b,c,d] → [b,c,d,a]`

**SubWord:** apply S-box to each byte of the word.

**Rcon:** round constants — successive powers of 2 (i.e., `x`) in GF(2⁸):

```
Rcon[1..10] = {01, 02, 04, 08, 10, 20, 40, 80, 1b, 36}
```

`0x1b` is `2⁸ mod p(x) = x⁴+x³+x+1`, `0x36 = 2·0x1b mod p(x)`.

### Round Key Matrix Packing

The 44 words are grouped 4 at a time into 4×4 matrices (same column-major order as the state):

```go
for rk := 0; rk < 11; rk++ {
    for col := 0; col < 4; col++ {
        for row := 0; row < 4; row++ {
            roundKeys[rk][row][col] = w[rk*4+col][row]
        }
    }
}
```

---

## Encryption and Decryption

### Encryption (10 rounds)

```
KeyExpansion(key) → rk[0..10]

state = toState(plaintext)
state = AddRoundKey(state, rk[0])          ← initial whitening

for round = 1 to 9:
    state = SubBytes(state)
    state = ShiftRows(state)
    state = MixColumns(state)
    state = AddRoundKey(state, rk[round])

state = SubBytes(state)                    ← final round (no MixColumns)
state = ShiftRows(state)
state = AddRoundKey(state, rk[10])

ciphertext = fromState(state)
```

The final round omits MixColumns. This makes encryption and decryption structurally symmetric and has no effect on security (the last round key would cancel it out anyway).

### Decryption (inverse rounds)

```
state = toState(ciphertext)
state = AddRoundKey(state, rk[10])

for round = 9 downto 1:
    state = InvShiftRows(state)
    state = InvSubBytes(state)
    state = AddRoundKey(state, rk[round])
    state = InvMixColumns(state)

state = InvShiftRows(state)
state = InvSubBytes(state)
state = AddRoundKey(state, rk[0])

plaintext = fromState(state)
```

Note the order: `InvShiftRows` before `InvSubBytes`. These two commute (ShiftRows only permutes byte positions; SubBytes operates on each byte independently), so the order is a matter of convention. `AddRoundKey` must come *between* InvSubBytes and InvMixColumns — not after — because AddRoundKey and InvMixColumns do not commute directly in this formulation.

---

## Usage

**Requirements:** Go 1.21+

```
git clone https://github.com/kiazh/AES-128
cd AES-128
go run .
```

The program offers three modes:

```
AES-128  —  choose mode
  1  Encrypt plaintext
  2  Decrypt ciphertext
  3  Run FIPS 197 test vector
```

**Encrypt:** enter 16 ASCII characters → outputs 32-hex-char ciphertext.

**Decrypt:** enter 32 hex characters → outputs plaintext.

**Test vector (mode 3):**

```
Plaintext  3243f6a8 885a308d 313198a2 e0370734
Key        2b7e1516 28aed2a6 abf71588 09cf4f3c
Expected   3925841d 02dc09fb dc118597 196a0b32
```

This vector is taken directly from FIPS 197, Appendix B.

---

## What's Implemented vs. Hardcoded

Quick map of what runs at runtime versus what is embedded as a constant, so there's no ambiguity about what this implementation actually computes:

| Component | Status |
| --- | --- |
| GF(2⁸) multiplication (`gmul`) | **Computed at runtime** via Russian Peasant double-and-add |
| MixColumns / InvMixColumns | **Computed at runtime** using `gmul` |
| Forward S-box | **Hardcoded** as the FIPS-197 256-byte literal |
| Inverse S-box | **Computed at startup** by inverting the forward S-box mapping |
| Round constants (`rcon[10]`) | **Hardcoded** as the FIPS-197 sequence |
| Key schedule (44 words → 11 round keys) | **Computed at runtime** from the input key |
| State packing / unpacking | **Computed at runtime** |
| Encryption / decryption (10 rounds) | **Computed at runtime** |

### Planned

* Generate the forward S-box from GF(2⁸) inverses + the affine transform, instead of using the hardcoded table.
* Replace mode-3's interactive FIPS check with a proper `aes_test.go` covering FIPS-197 Appendix A (key expansion) and Appendix B (block encryption) vectors.

---

## Security Notes

This implementation is **educational**. It is not hardened for production use:

* **No constant-time execution.** The `gmul` loop and S-box lookup are data-dependent. A real implementation must use constant-time table lookups or bitslicing to resist cache-timing attacks (e.g. Bernstein's 2005 AES cache-timing attack).
* **No modes of operation.** This encrypts exactly one 16-byte block with a fixed key. Real systems need CBC, CTR, GCM, etc. to handle arbitrary-length messages and provide semantic security.
* **Fixed key in CLI.** The `main.go` key `2b7e151628aed2a6abf7158809cf4f3c` is the FIPS test key — not for real use.
* **No key zeroisation.** Round keys remain in memory after use. A hardened implementation should zero them with `runtime.KeepAlive` + `unsafe` or a dedicated scrubbing function.

For production Go code use `crypto/aes` from the standard library, which uses AES-NI hardware instructions and is constant-time.

---

## References

* FIPS 197 — *Advanced Encryption Standard*, NIST (2001)
* Joan Daemen, Vincent Rijmen — *The Design of Rijndael* (2002)
* D.J. Bernstein — *Cache-timing attacks on AES* (2005)
