\input amssym

\def\title{SHA-256}
\def\topofcontents{\null\vfill
    \centerline{\titlefont The SHA-256 algorithm}
    \vfill}
    
\def\botofcontents{\vfill
\noindent
Copyright \copyright\ 2002 Brute Squad Labs, Inc.

\bigskip\noindent
Permission is granted to make and distribute verbatim copies of this
document provided that the copyright notice and this permission notice
are preserved on all copies.

\smallskip\noindent
Permission is granted to copy and distribute modified versions of this
document under the conditions for verbatim copying, provided that the
entire resulting derived work is given a different name and distributed
under the terms of a permission notice identical to this one.
}

\datethis
@*Introduction. What follows is an implementation of the SHA-256 cryptographic
message digest algorithm as defined in (still draft) FIPS PUB 180-2. It actually
works, and I've put in the unit tests that came with the spec --- define the
preprocessor symbol |UNIT_TEST| to enable them.

This was largely an experiment on my part to see how easy and useful it is to
``program literately'', and I tell you --- it really is a lot of fun.

But is it really useful? I mean, if you were going to write 120,000 lines of
code, would it work? I imagine that Knuth thinks so, since he did \TeX\ that
way.

Let me mess with it some more. Enjoy this literary feast (well, OK, literary
snack), and when you're done snacking, go ahead and run it. Kinda like eating
the shell your taco salad comes in --- it's a bowl as well as a snack.

\smallskip\rightline{--- Blake Ramsdell, July 2002}
\rightline{\pdfURL{Brute Squad Labs, Inc.}{http://www.brutesquadlabs.com}}

@s sha_256_context int
@s byte int
@s uint32 int

@ In order to digest data with SHA-256, you simply call |sha_256_init| followed
by one or more calls to |sha_256_update| and then ultimately call
|sha_256_final|. The resulting digest is stored in the byte array member
|final_digest| of the |sha_256_context| structure.

@c
#include <memory.h>

@<Type definitions@>@;
@<Global constants@>@;
@<Underlying functions@>@;

void sha_256_init(sha_256_context* context)
{
    @<Set |H|...@>@;
    @<Initialize the current message block...@>@;
}

void sha_256_update(sha_256_context* context, uint32 data_length, const byte* data)
{
    while (data_length > 0)
    {
        uint32 bytes_to_copy = min(remaining_bytes_in_block, data_length);
    
        @<Append data to...@>@;
        @<Update hash...@>@;
    
        data_length -= bytes_to_copy;
        data += bytes_to_copy;
    }
}

void sha_256_final(sha_256_context* context)
{
    uint32 total_data_processed_bits = context->total_data_processed_bytes * 8;
    byte temp_buffer[sizeof(context->M)];

    @<Append padding to the end of the message@>@;
    @<Append length...@>@;
    @<Expand the final digest@>@;
}

@*Type definitions, macros and constants.

@ For SHA-256, the number of bits in a word, $w$, is 32. We will use the uint32
datatype for almost all variables.

@<Type definitions@>=
typedef unsigned int uint32;

@ A byte datatype is useful also.

@<Type definitions@>=
typedef unsigned char byte;

@ The |rotr| macro is used for rotating a |uint32|, |X|, |N| bits to the right.

@d rotr(X, N) ((X >> N) | (X << (32 - N)))

@ Good ol' |min|. Nothing beats that. Except maybe |max|, but he's not here.

@d min(X, Y) (((X) < (Y)) ? (X) : (Y))

@ |remaining_bytes_in_block| figures out the number of bytes remaining in the
current message block, $M^{(i)}$.

@d remaining_bytes_in_block (sizeof(context->M) - context->current_block_length_bytes)

@ The array |K| corresponds to the sequence $K^{\{256\}}$ defined in FIPS 180-2
\S4.2.2. According to that section, ``These words represent the first thirty-two
bits of the fractional parts of the cube roots of the first sixty four prime
numbers$\ldots$''

@<Global constants@>=
static uint32 K[64] = {
0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

@ We will use a context object to retain information in between calls to
|sha_256_update|.

@<Type definitions@>=
typedef struct
{
    @<Context data@>
} sha_256_context;

@ The last hash value, $H^{(i-1)}$

@<Context data@>=
uint32 H[8];

@ The current block of the message, $M^{(i)}$, $m$ bits long. $m = 512$ for
SHA-256.

@<Context data@>=
byte M[512 / 8]; /* Blocks are 512 bits long */
uint32 current_block_length_bytes;

@ The total number of bytes in the message so far, $(l * 8)$, since $l$ is in
bits.
 
@<Context data@>=
uint32 total_data_processed_bytes;

@ The final digest value, $H^{(N)}$

@<Context data@>=
byte final_digest[32];

@*Underlying functions. There are several primitive functions for SHA-256.

@ The function Ch as defined in FIPS 180-2 \S4.1.2.

$${\rm Ch}(x,y,z) = (x \land y) \oplus (\lnot x \land z)$$

@<Underlying functions@>=
uint32 Ch(uint32 x, uint32 y, uint32 z)
{
    return (x & y) ^ (~x & z);
}

@ The function Maj as defined in FIPS 180-2 \S4.1.2.

$${\rm Maj}(x,y,z) = (x \land y) \oplus (x \land z) \oplus (y \land z)$$

@<Underlying functions@>=
uint32 Maj(uint32 x, uint32 y, uint32 z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

@ The function |sigma0| corresponds to the function $\sigma_0^{\{256\}}$ in
FIPS 180-2 \S4.1.2.

$$\sigma_0^{\{256\}}(x) = (x \ggg 7) \oplus (x \ggg 18) \oplus (x \gg 3)$$

@<Underlying functions@>=
uint32 sigma0(uint32 x)
{
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

@ The function |sigma1| corresponds to the function $\sigma_1^{\{256\}}$ in
FIPS 180-2 \S4.1.2.

$$\sigma_1^{\{256\}}(x) = (x \ggg 17) \oplus (x \ggg 19) \oplus (x \gg 10)$$

@<Underlying functions@>=
uint32 sigma1(uint32 x)
{
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

@ The function |Sigma0| corresponds to the function $\Sigma_0^{\{256\}}$ in
FIPS 180-2 \S4.1.2.

$$\Sigma_0^{\{256\}}(x) = (x \ggg 2) \oplus (x \ggg 13) \oplus (x \ggg 22)$$

@<Underlying functions@>=
uint32 Sigma0(uint32 x)
{
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

@ The function |Sigma1| corresponds to the function $\Sigma_1^{\{256\}}$ in
FIPS 180-2 \S4.1.2.

$$\Sigma_1^{\{256\}}(x) = (x \ggg 6) \oplus (x \ggg 11) \oplus (x \ggg 25)$$

@<Underlying functions@>=
uint32 Sigma1(uint32 x)
{
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

@*Preprocessing. Prepares the |sha_256_context| structure for first use. 

@ The current hash value, $H$, is set to $H^{(0)}$ per the values in FIPS 180-2
\S5.3.2. According to that section, ``These words were obtained by taking the
first thirty-two bits of the fractional parts of the square roots of the first
eight prime numbers.''

@<Set |H| to the initial value, $H^{(0)}$@>=
context->H[0] = 0x6a09e667;
context->H[1] = 0xbb67ae85;
context->H[2] = 0x3c6ef372;
context->H[3] = 0xa54ff53a;
context->H[4] = 0x510e527f;
context->H[5] = 0x9b05688c;
context->H[6] = 0x1f83d9ab;
context->H[7] = 0x5be0cd19;

@ The current block size and the total number of bytes processed are zeroed. 
 
@<Initialize the current message block, $M^{(0)}$@>=
context->current_block_length_bytes = 0;
context->total_data_processed_bytes = 0;

@*Hash computation. The code in here is for implementing the methods of FIPS
180-2 \S6.2 in order to compute the current hash value, $H^{(i)}$ for the
current message block, $M^{(i)}$.

@ The general strategy is as follows

@<Compute the intermediate hash value, $H^{(i)}$@>=
{
    uint32 a, b, c, d, e, f, g, h;
    uint32 t;
    uint32 T1, T2;
    uint32 W[64];
    
    @<Initialize working...@>@;
    
    for (t = 0;t < 64;++t)
    {
        @<Compute the message schedule...@>@;
        
        @<Compression...@>@;
    }
    
    @<Copy the intermediate...@>@;
    
    context->current_block_length_bytes = 0;
}

@ FIPS 180-2 \S6.2.2 specifies in step 2 the initialization of eight working
variables $a, b, \ldots, h$ to the current value of $H$ (which is the hash value
for the previous block, and thus represents $H^{(i-1)}$.)

I believe that there is an inconsistency in the specification since the prose
reads ``Initialize$\ldots$with the $(i-1)$ hash value'' and the assignments that
follow use components of $H^{(i)}$.

@<Initialize working variables from $H^{(i-1)}$@>=
a = context->H[0];
b = context->H[1];
c = context->H[2];
d = context->H[3];
e = context->H[4];
f = context->H[5];
g = context->H[6];
h = context->H[7];

@ FIPS 180-2 \S6.2.2 specifies in step 1 to compute $W_t$.
 
$$W_t\gets\left\{\matrix{
M_t^{(i)} \hfill & 0 \leq t \leq 15\hfill\cr
\sigma_1^{\{256\}}(W_{t-2})+W_{t-7}+\sigma_0^{\{256\}}(W_{t-15}) + W_{t-16} \hfill&
16 \leq t \leq 63\hfill\cr}
\right.$$

@<Compute the message schedule, $W_t$@>=
if (t <= 15)
{
    W[t] =
        (context->M[t * 4] << 24) |
        (context->M[(t * 4) + 1] << 16) |
        (context->M[(t * 4) + 2] << 8) |
        (context->M[(t * 4) + 3]);
}
else
{
    W[t] =
        sigma1(W[t-2]) +
        W[t-7] +
        sigma0(W[t-15]) +
        W[t-16];
}

@ The compression function, as specified in FIPS 180-2 \S6.2.2 step 3.

@<Compression function@>=
T1 = h + Sigma1(e) + Ch(e, f, g) + K[t] + W[t];
T2 = Sigma0(a) + Maj(a, b, c);
h = g;
g = f;
f = e;
e = d + T1;
d = c;
c = b;
b = a;
a = T1 + T2;

@ Finally we assign the current intermediate hash value, $H^{(i)}$ to |H| in the
context, per FIPS 180-2 \S6.2.2 step 3.

@<Copy the intermediate hash value, $H^{(i)}$@>=
context->H[0] += a;
context->H[1] += b;
context->H[2] += c;
context->H[3] += d;
context->H[4] += e;
context->H[5] += f;
context->H[6] += g;
context->H[7] += h;

@*Message block processing.

@ Append some data to the message block, possibly filling the block.

@<Append data to the current message block, $M^{(i)}$@>=
memcpy(context->M + context->current_block_length_bytes, data, bytes_to_copy);
context->current_block_length_bytes += bytes_to_copy;
context->total_data_processed_bytes += bytes_to_copy;

@ In the event that the current block is full, then compute the intermediate
hash value, $H^{(i)}$.

@<Update hash if required@>=
if (remaining_bytes_in_block == 0)
{
    @<Compute the intermediate...@>@;
}

@* Final block processing. We need to jam a single 1 bit, followed by some
number of 0 bits followed by 64 bits of the length (in bits) of the data that
has been digested (from FIPS 180-2 \S5.1.1). Finally, we make a byte array copy
of the final digest value, $H^{(N)}$.

@ The padding length is computed to leave enough space for the eight byte
length, and then added to the message.

@<Append padding to the end of the message@>=
temp_buffer[0] = 0x080; // Our one bit plus seven zero bits

sha_256_update(context, 1, temp_buffer);

memset(temp_buffer, 0, sizeof(temp_buffer));
    
if (remaining_bytes_in_block < 8)
{
    // Fill up this block
    
    sha_256_update(context, remaining_bytes_in_block, temp_buffer);
}

sha_256_update(context, remaining_bytes_in_block - 8, temp_buffer);

@ The eight byte length is then appended to the message.

@<Append length to the end of the message@>=

temp_buffer[4] = (total_data_processed_bits >> 24) & 0x0FF;
temp_buffer[5] = (total_data_processed_bits >> 16) & 0x0FF;
temp_buffer[6] = (total_data_processed_bits >> 8) & 0x0FF;
temp_buffer[7] = (total_data_processed_bits) & 0x0FF;

sha_256_update(context, 8, temp_buffer);

@ Make a copy of the final digest block, $H^{(N)}$, converted to a byte array.

@<Expand the final digest@>=
{
int counter;

for (counter = 0;counter < (sizeof(context->H) / sizeof(context->H[0]));++counter)
{
    context->final_digest[(counter * 4) + 0] = ((context->H[counter] >> 24) & 0x0ff);
    context->final_digest[(counter * 4) + 1] = ((context->H[counter] >> 16) & 0x0ff);
    context->final_digest[(counter * 4) + 2] = ((context->H[counter] >> 8) & 0x0ff);
    context->final_digest[(counter * 4) + 3] = ((context->H[counter]) & 0x0ff);
}
}

@*Unit tests. The following section implements the unit tests for this module.
The unit tests will only be included in the event that the \CEE/ preprocessor
symbol |UNIT_TEST| is |#define|d.

@c
#ifdef UNIT_TEST

#include <stdio.h> /* Just for |printf| */

@<Unit tests@>@;

int main(int argc, char** argv)
{
    @<Run unit tests@>@;

    return 0;
}

#endif

@ Each unit test will use this macro to print its output. It uses the function
name for the output test name.

@d assert_final_digest_equal() assert_byte_arrays_equal(__func__, expected_value, sizeof(expected_value), context.final_digest, sizeof(context.final_digest))

@ Helper test function for making sure two byte arrays are equal.

@<Unit tests@>=
void assert_byte_arrays_equal(
    const char* test_name,
    const byte* expected_value,
    int expected_value_length,
    const byte* actual_value,
    int actual_value_length)
{
    printf("%s %s\n", ((expected_value_length != actual_value_length) ||
                       (memcmp(expected_value, actual_value, actual_value_length) != 0)) ?
                         "FAIL" : "PASS", test_name);
}

@ FIPS 180-2 \S{}B.1, hashing the string |"abc"|

@<Unit tests@>=
void test_B1()
{
    const byte expected_value[] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
        };
    sha_256_context context;
    
    sha_256_init(&context);
    sha_256_update(&context, 3, (const byte*) "abc");
    sha_256_final(&context);
    
    assert_final_digest_equal();
}

@ @<Run unit tests@>=
test_B1();  

@ FIPS 180-2 \S{}B.2, hashing the string |"abcdbc..."|

@<Unit tests@>=
void test_B2()
{
    const byte expected_value[] = {
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
        0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
        0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
        0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1
        };
    sha_256_context context;
    
    sha_256_init(&context);
    sha_256_update(&context, 56, (const byte*) "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    sha_256_final(&context);
    
    assert_final_digest_equal();
}

@ @<Run unit tests@>=
test_B2();  

@ FIPS 180-2 \S{}B.3, hashing the byte |'a'| 1,000,000 times (1,000 calls to
|sha_256_update| with 1,000 |'a'|s apiece.)

@<Unit tests@>=
void test_B3()
{
    const byte expected_value[] = {
        0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92,
        0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7, 0x3e, 0x67,
        0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e,
        0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0
        };
    sha_256_context context;
    byte data_block[1000];
    int counter = 0;
    
    memset(data_block, 'a', sizeof(data_block));
    
    sha_256_init(&context);
    for (counter = 0;counter < 1000;++counter)
    {
        sha_256_update(&context, sizeof(data_block), data_block);
    }
    sha_256_final(&context);
    
    assert_final_digest_equal();
}

@ @<Run unit tests@>=
test_B3();  


@* Index. {\tt CWEAVE} likes to make it, so why should I complain? Hopefully you
find what you're looking for in it.

