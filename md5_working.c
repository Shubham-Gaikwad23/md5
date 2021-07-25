#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// non-linear function used during rounds
#define FUN_F(B, C, D) (((B) & (C)) | (~(B) & (D)))
#define FUN_G(B, C, D) (((B) & (D)) | ((C) & ~(D)))
#define FUN_H(B, C, D) ((B) ^ (C) ^ (D))
#define FUN_I(B, C, D) ((C) ^ ((B) | ~(D)))

// leftrotate function definition
#define LEFTROTATE(X, C) (((X) << (C)) | ((X) >> (32 - (C))))

// 128-bit buffer storing state
typedef struct State
{
    uint32_t A;
    uint32_t B;
    uint32_t C;
    uint32_t D;
} State;

uint8_t * md5(uint8_t *init_msg, size_t init_len);
void update(State *original_state, const uint32_t msg[16]);
static uint8_t * pad_msg(uint8_t *init_msg, size_t init_len, size_t *new_len);

uint8_t * md5(uint8_t *init_msg, size_t init_len)
{
    size_t len = 0;
    const uint8_t *msg = pad_msg(init_msg, init_len, &len);

    // Initial state of buffer
    State state = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476}; 
    // Run for all msg blocks
    for (size_t i = 0; i < len; i += 64)
        update(&state, (uint32_t *)msg + i);

    uint8_t *digest = malloc(sizeof(uint8_t) * 128);
    memcpy(digest, &state.A, sizeof(uint32_t));
    memcpy(digest+4, &state.B, sizeof(uint32_t));
    memcpy(digest+8, &state.C, sizeof(uint32_t));
    memcpy(digest+12, &state.D, sizeof(uint32_t));

    return digest;
}

void update(State *original_state, const uint32_t *msg)
{
    // shifts specifies the per-round shift amounts
    short shifts[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                      5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
                      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

    // constants to be used during rounds
    size_t constants[] = {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                          0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                          0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                          0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                          0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                          0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                          0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                          0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                          0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                          0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                          0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
                          0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                          0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
                          0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                          0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                          0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

    State state = *original_state;

    for (int i = 0; i < 64; i++)
    {
        uint32_t fun_out, g;
        if (i < 16)
        {
            fun_out = FUN_F(state.B, state.C, state.D);
            g = i;
        }
        else if (i < 32)
        {
            fun_out = FUN_G(state.B, state.C, state.D);
            g = (5 * i + 1) % 16;
        }
        else if (i < 48)
        {
            fun_out =  FUN_H(state.B, state.C, state.D);
            g = (3 * i + 5) % 16;
        }
        else
        {
            fun_out =  FUN_I(state.B, state.C, state.D);
            g = (7 * i) % 16;
        }

        fun_out += state.A + constants[i] + msg[g];
        state.A = state.D;
        state.D = state.C;
        state.C = state.B;
        state.B = state.B + LEFTROTATE(fun_out, shifts[i]);
    }

    original_state->A += state.A;
    original_state->B += state.B;
    original_state->C += state.C;
    original_state->D += state.D;
}

static uint8_t *
pad_msg(uint8_t *init_msg, size_t init_len, size_t *new_len)
{
    // Calculate length of message after padding
    *new_len = ((((init_len + 8) / 64) + 1) * 64) - 8;
    // New block with more size than original msg required to store padding and length of original msg
    uint8_t *msg = calloc(*new_len + 8, sizeof(uint8_t));
    // Copy the original msg
    memcpy(msg, init_msg, init_len);
    // Append 1 at the end of msg
    msg[init_len] = 128;
    // we append the length of original message in bits
    uint64_t bits_len = 8 * init_len;
    // at the end of the buffer
    memcpy(msg + *new_len, &bits_len, sizeof(uint64_t));
    *new_len += 8;

    return msg;
}

void main()
{
    uint8_t *msg = "The quick brown fox jumps over the lazy dog";
    uint8_t *digest = md5(msg, 43);
    printf("MD5 of \"%s\" is \n\n", msg);
    for(int i=0; i<16; i++)
        printf("%x", digest[i]);
    printf("\n\n");
}
