## This is a simple implementation of md5 hash algorithm in C. The purpose is to understand the working of the function.

"Message digest algorithm 5" is commonly used in cryptography which takes a variable length binary input and produces a fixed length binary output of 128 bits. As an Internet standard [(RFC 1321)](https://www.ietf.org/rfc/rfc1321.txt/), MD5 has been employed in a wide variety of security applications, and is also commonly used to check the integrity of files. An MD5 hash is typically expressed as a 32 digit hexadecimal number.

## Overview
![Overview](https://github.com/Shubham-Gaikwad23/md5/blob/master/300px-MD5_algorithm.svg.png)

Figure 1. One MD5 operation. MD5 consists of 64 of these operations, grouped in four rounds of 16 operations. $F$ is a nonlinear function; one function is used in each round. M[i] denotes a 32-bit block of the message input, and K[i] denotes a 32-bit constant, different for each operation. <<<s denotes a left bit rotation by s places; s varies for each operation. Red square with '+' inscribed denotes addition modulo $2^{32}$.

## Algorithm

MD5 operates on 32-bit words. Let M be the message to be hashed. The message M is padded so that its length (in bits) is equal to 448 modulo 512, that is, the padded message is 64 bits less than a multiple of 512. The padding consists of a single 1 bit, followed by enough zeros to pad the message to the required length. Padding is always used, even if the length of M happens to equal 448 mod 512. As a result, there is at least one bit of padding, and at most 512 bits of padding. Then the length (in bits) of the message (before padding) is appended as a 64-bit block.

The padded message is a multiple of 512 bits and, therefore, it is also a multiple of 32 bits. Let M be the message and N the number of 32-bit words in the (padded) message. Due to the padding, N is a multiple of 16.

A four-word buffer (A,B,C,D) is used to compute the message digest. Here each of A, B, C, D is a 32-bit register. These registers are initialized to the following values in hexadecimal:

```
word A: 01 23 45 67
word B: 89 ab cd ef
word C: fe dc ba 98
word D: 76 54 32 10
```
We first define four auxiliary functions that each take as input three 32-bit words and produce as output one 32-bit word.

![Functions](https://github.com/Shubham-Gaikwad23/md5/blob/master/fun.png/)

