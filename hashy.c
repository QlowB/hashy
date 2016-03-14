/*
 * hashy hash function
 * Copyright (C) 2016 Nicolas Winkler
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// I think this does nothing, still, let's try
#pragma GCC optimize("no-strict-aliasing")

/// type used as hash value is a 128 bit wide integer type
typedef union int_128 {
    struct {
        uint64_t lower;
        uint64_t upper;
    };
        
    unsigned char bytes[16];
} int_128;


// some function definitions
static void digestStream(FILE* stream, int_128* val);
static void digestBlock(unsigned char* data, int_128* val, size_t size);
static void printHex(int_128* val);
static void xor_int128(int_128* result, int_128* op);
static void mult(int_128* result, int_128* factor);
static void shuffle(int_128* val);
static uint8_t permute8bits[];


/// for those not familiar with c: this is where program starts!
int main(int argc, char** argv)
{
    // if file names were specified as arguments
    if (argc > 1) {
        // process them all separately
        for (int i = 1; i < argc; i++) {
            FILE* input = fopen(argv[i], "r");
            int_128 hash;
            if (input) {
                digestStream(input, &hash);
                printf("hashy (%s) = ", argv[i]);
                printHex(&hash);
                fclose(input);
            }
            else
                fprintf(stderr, "\x1B[31;1m" "error: " "\x1b[0m"
                        "unable to open file %s\n", argv[i]);
        }
    }
    // otherwise process standard input
    else {
        int_128 hash;
        digestStream(stdin, &hash);
        printHex(&hash);
    }
}


/// process data coming from a data stream
void digestStream(FILE* stream, int_128* val)
{
    val->upper = 0;
    val->lower = 0;

    // read blocks of 1024 bytes
    const int blockSize = 1024;

    // buffer to read blocks
    unsigned char c[blockSize];

    // stores the number of bytes read during the last read operation
    size_t read = 0;

    // stores number of bytes read in total
    uint64_t totalRead = 0;

    // if totalRead has been appended to the end of the data stream
    int numAppended = 0;

    // keep reading chunks as long as there is data
    while ((read = fread(&c, 1, sizeof c, stream)) != 0) {
        totalRead += read;
        memset(c + read, 0, sizeof c - read);

        // append number of bytes read in total
        if (sizeof c - read >= 32) {
            uint64_t* cnt = (uint64_t*) (c + sizeof c - 32);
            *cnt = totalRead;
            numAppended = 1;
        }

        // nom nom nom
        digestBlock(c, val, sizeof c);

        // on eof
        if (read != sizeof c)
            break;
        read = 0;
    }

    // if number of bytes read not yet appended
    if (!numAppended) {
        memset(c, 0, sizeof c);
        uint64_t* cnt = (uint64_t*) (c + sizeof c - 32);
        *cnt = totalRead;
        // last nom nom
        digestBlock(c, val, sizeof c);
    }
}


/// process one block of input data
static void digestBlock(unsigned char* data, int_128* val, size_t size)
{
    // iterate through whole block
    for (size_t i = 0; i < size; i += sizeof(int_128)) {
        int_128* v = (int_128*) &data[i];
        xor_int128(val, v);
        for (int j = 0; j < 10; j++)
            shuffle(val);
    }
}


/// xors two 128-bit integers together into the first argument
static void xor_int128(int_128* result, int_128* op)
{
    result->upper ^= op->upper;
    result->lower ^= op->lower;
}


/// 16-bit permutation table
static uint16_t* permute16bits = NULL;
/// prepares the faster array.
///
/// Converts the 8-bit permutation table into a 16-bit permutation table
/// so two bytes can be looked up at once.
///
static void initFasterShuffle(void)
{
    size_t size = (1 << 16);
    permute16bits = malloc(size * sizeof (uint16_t));

    if (!permute16bits)
        return;

    for (size_t i = 0; i < size; i++) {
        uint8_t lower = i & 0xFF;
        uint8_t upper = i >> 8;
        permute16bits[i] = (permute8bits[lower] << 8) | (permute8bits[upper]);
    }
}


/// performs some shuffling on the bits
static void shuffle(int_128* val)
{
    uint64_t l = val->lower;
    uint64_t u = val->upper;
    uint64_t nl = 0;
    uint64_t nu = 0;

    size_t fastCounter = 0;

    // invert order of bytes and permute every byte
    if (permute16bits) {
        for (int i = 0; i < 4; i++) {
            nu |= permute16bits[l & 0xFFFF];
            nl |= permute16bits[u & 0xFFFF];
            if (i < 3) {
                nu <<= 16; nl <<= 16;
                l >>= 16; u >>= 16;
            }
        }
    }
    else {
        fastCounter++;
        if (fastCounter == (1 << 16))
            initFasterShuffle();
        for (int i = 0; i < 4; i++) {
            nu |= permute8bits[l & 0xFF];
            nl |= permute8bits[u & 0xFF];
            if (i < 7) {
                nu <<= 8; nl <<= 8;
                l >>= 8; u >>= 8;
            }
        }
    }
    val->upper = nu;
    val->lower = nl;


    // perform some xorshift
    val->upper   ^= (val->lower << 23) | (val->lower >> (64 - 23));
    val->lower   ^= (val->upper << 17) | (val->upper >> (64 - 17));

    
    // rotate 128 bits
    uint64_t temp = (val->upper << 47) | (val->lower >> (64 - 47));
    val->lower    = (val->lower << 47) | (val->upper >> (64 - 47));
    val->upper    = temp;
}


/// print hexadecimal representation of val
static void printHex(int_128* val)
{
    unsigned char* c = val->bytes;
    for (int i = 15; i >= 0; i--) {
        printf("%x", (int) (c[i] & 0xF));
        printf("%x", (int) (c[i] >> 4));
    }
    puts("");
}


/// permutation table for 8-bit values
static uint8_t permute8bits[] = {
    150, 130, 8, 186, 3, 179, 213, 64, 123, 45, 41,
    99, 250, 175, 48, 7, 226, 97, 177, 185, 191, 108, 94, 231, 220, 68, 74,
    133, 162, 2, 116, 122, 193, 182, 255, 249, 73, 47, 209, 238, 233, 30, 119,
    11, 245, 154, 54, 136, 21, 85, 225, 232, 203, 10, 5, 66, 176, 157, 56, 76,
    120, 229, 197, 178, 221, 195, 217, 104, 135, 204, 49, 244, 149, 63, 151,
    33, 121, 77, 196, 95, 242, 215, 67, 251, 212, 101, 254, 23, 160, 164, 222,
    103, 91, 208, 236, 216, 52, 26, 25, 218, 61, 1, 139, 90, 143, 58, 152, 140,
    246, 50, 159, 31, 207, 53, 147, 0, 84, 80, 35, 155, 106, 59, 126, 214, 189,
    111, 131, 174, 112, 248, 172, 39, 252, 51, 107, 36, 138, 125, 16, 134, 228,
    158, 156, 57, 62, 93, 148, 6, 70, 29, 190, 15, 241, 200, 205, 71, 89, 42,
    132, 22, 224, 166, 198, 118, 32, 17, 37, 55, 235, 100, 161, 88, 223, 24,
    92, 201, 113, 12, 243, 173, 14, 27, 34, 183, 247, 86, 75, 240, 171, 170,
    109, 65, 115, 230, 124, 163, 192, 82, 142, 145, 72, 227, 234, 187, 18, 105,
    202, 194, 60, 4, 79, 199, 117, 40, 165, 127, 46, 69, 114, 102, 169, 20, 98,
    128, 78, 184, 96, 9, 28, 38, 210, 188, 83, 137, 211, 181, 44, 206, 43, 81,
    253, 219, 153, 239, 146, 167, 168, 87, 129, 13, 110, 144, 180, 237, 19, 141
};



