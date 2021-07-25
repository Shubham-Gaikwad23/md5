#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

// Underlying architecture is assumed to be little-endian.

//  Variable s is the array that holds shift amount constants
//  According to RFC 1321 - The shift amounts in each round have been approximately optimized,
//  to yield a faster "avalanche effect." The shifts in different rounds are distinct.
//  Small changes in current state results into massive changes in final output is avalanch effect.
unsigned int s[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

// K is the array of round constants. There are 64 rounds and each has a unique constant
unsigned int K[64] = {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};
unsigned int i;

// Initialization Vector: values are in accordance with RFC 1321
// There are four buffers in MD5 - A, B, C and D, each of 32 bits and concatenation of A+B+C+D of 128 bits is known as 'state'.
unsigned int a0 = 0x67452301; // A
unsigned int b0 = 0xefcdab89; // B
unsigned int c0 = 0x98badcfe; // C
unsigned int d0 = 0x10325476; // D

// Define left rotate using left shift operator of C
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

void md5(unsigned char *init_msg, size_t init_len)
{
    uint8_t *msg = NULL;

    //	The given message is of variable length. We have to add 1 bit compulsory padding and then
    //	calculate how many blocks of 512 bits will be generated and how many zeros will be padded to make
    //	the last block as a multiple of 512 bit.
    int new_len = ((((init_len + 8) / 64) + 1) * 64) - 8; // This formula calculates length of message after padding.

    msg = calloc(new_len + 64, 1); // also appends "0" bits: calloc will auto initilize with 0
                                   // (we alloc also 64 extra bytes...)

    memcpy(msg, init_msg, init_len); // write the original message to 'msg'
    msg[init_len] = 128;             // write the "1" bit at the end as compulsory padding.
                                     // remember we do not need to write 0 bits as padding because of calloc

    uint32_t bits_len = 8 * init_len;    // note, we append the len of original message in bits
    memcpy(msg + new_len, &bits_len, 4); // at the end of the buffer

    // Process the message in successive 512-bit chunks:
    //for each 512-bit chunk of message:
    int offset;
    for (offset = 0; offset < new_len; offset += (512 / 8))
    {
        uint32_t *w = (uint32_t *)(msg + offset); // break chunk into sixteen 32-bit words w[j], 0 = j = 15

        unsigned int A = a0; // Initialize hash value for this chunk:
        unsigned int B = b0; // For next 512 bit block, digest of previous block added with the IV of previos block
        unsigned int C = c0; // will be used as IV of next round
        unsigned int D = d0;

        for (i = 0; i < 64; i++) //64 rounds
        {
            unsigned int F, g;
            if (i < 16)
            {
                F = (B & C) | ((~B) & D); //Function F
                g = i;
            }
            else if (i < 32)
            {
                F = (D & B) | ((~D) & C); //Function G
                g = (5 * i + 1) % 16;
            }
            else if (i < 48)
            {
                F = B ^ C ^ D; //Function H
                g = (3 * i + 5) % 16;
            }
            else
            {
                F = C ^ (B | (~D)); //Function I
                g = (7 * i) % 16;
            }

            //The following process is best explained by the figure 1 in .md file
            unsigned temp = D;
            D = C;
            C = B;
            B = B + LEFTROTATE((A + F + K[i] + w[g]), s[i]);
            A = temp;
        }
        a0 = a0 + A; //Generate the IV for next round
        b0 = b0 + B;
        c0 = c0 + C;
        d0 = d0 + D;
    }
}

int main()
{
    unsigned char *p;

    unsigned char msg[1024 * 1024];
    printf("Enter your message : ");
    gets(msg);

    md5(msg, strlen(msg));
    printf("MD5 hash is : ");

    p = (uint8_t *)&a0;
    printf("%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3], a0);

    p = (uint8_t *)&b0;
    printf("%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3], b0);

    p = (uint8_t *)&c0;
    printf("%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3], c0);

    p = (uint8_t *)&d0;
    printf("%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3], d0);
    puts("");

    return 0;
}
