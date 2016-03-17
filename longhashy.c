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


#define nParts ((BITS) / 64)

/// type used as hash value is a 256 bit wide integer type
typedef union big_int {
    uint64_t part[nParts];
    uint8_t bytes[nParts * sizeof(uint64_t)];
} int_256;

typedef int_256 HashType;

// some function definitions
static void digestStream(FILE* stream, HashType* val);
static void digestBlock(HashType* data, HashType* val, size_t nElements);
static void printHex(HashType* val);
static void xor_bigint(HashType* result, HashType* op);
static void mult(HashType* result, HashType* factor);
static void shuffle(HashType* val);
static uint8_t permute8bits[];


/// for those not familiar with c: this is where program starts!
int main(int argc, char** argv)
{
    // if file names were specified as arguments
    if (argc > 1) {
        // process them all separately
        for (int i = 1; i < argc; i++) {
            FILE* input = fopen(argv[i], "r");
            HashType hash;
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
        HashType hash;
        digestStream(stdin, &hash);
        printHex(&hash);
    }
}


/// process data coming from a data stream
void digestStream(FILE* stream, HashType* val)
{
    memset(val->bytes, 0, sizeof (HashType));

    // read 8 blocks at once
    const size_t blockSize = 8;

    // buffer to read blocks
    HashType buffer[blockSize];

    // stores the number of bytes read during the last read operation
    size_t read = 0;

    // stores number of bytes read in total
    uint64_t totalRead = 0;
    
    // keep reading chunks as long as there is data
    while ((read = fread(&buffer, 1, sizeof buffer, stream)) != 0) {
        totalRead += read;
        memset(((char*) buffer) + read, 0, sizeof buffer - read);
        
        // nom nom nom
        digestBlock(buffer, val, blockSize);

        // on eof
        if (read != sizeof buffer)
            break;
        read = 0;
    }

    // if number of bytes read not yet appended
    memset(buffer, 0, sizeof buffer);
    buffer[0].part[0] = totalRead;
    // last nom nom
    digestBlock(buffer, val, blockSize);
}


/// process one block of input data
static void digestBlock(HashType* data, HashType* val, size_t nElements)
{
    // iterate through whole block
    for (size_t i = 0; i < nElements; i ++) {
        xor_bigint(val, data + i);
        for (int j = 0; j < 10; j++)
            shuffle(val);
    }
}


/// xors two 128-bit integers together into the first argument
static void xor_bigint(HashType* result, HashType* op)
{
    for (int i = 0; i < nParts; i++)
        result->part[i] ^= op->part[i];
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
static void shuffle(HashType* restrict val)
{
    uint64_t newVals[nParts];
    memset(newVals, 0, sizeof newVals);
    size_t fastCounter = 0;

    // invert order of bytes and permute every byte
    if (permute16bits) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < nParts; j++)
                newVals[j] |= permute16bits[val->part[nParts - j -1] & 0xFFFF];
            if (i < 3) {
                for (int k = 0; k < nParts; k++) {
                    newVals[k] <<= 16;
                    val->part[k] >>= 16;
                }
            }
        }
    }
    else {
        fastCounter++;
        if (fastCounter == (1 << 16))
            initFasterShuffle();
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < nParts; j++)
                newVals[j] |= permute8bits[val->part[nParts - j - 1] & 0xFF];
            if (i < 7) {
                for (int k = 0; k < nParts; k++) {
                    newVals[k] <<= 8;
                    val->part[k] >>= 8;
                }
            }
        }
    }
    for (int i = 0; i < nParts; i++) {
        if (newVals[i] & 0x40000ULL)
            val->part[i] = newVals[i];
        else
            val->part[i] = newVals[i] * 3762768456805741661ULL;
    }

    // rotate, shuffle and xor parts
    const uint8_t sh[] = {
        41, 7, 13, 33, 23, 3, 21, 61, 35, 11, 62, 5, 47, 45, 53, 27, 51, 31,
        29, 57, 17, 2, 37, 43, 59, 19
    };
    for (int i = 0; i < nParts; i++)
        newVals[i] = (val->part[i] << sh[i % sizeof sh]) |
            (val->part[i] >> (64 - sh[i % sizeof sh]));

    for (int i = 0; i < nParts; i++) {
        int ind = (i ^ sh[i % sizeof sh]) % nParts;
        if (nParts == 1)
            val->part[i] ^= newVals[ind];
        else
            val->part[i] ^= newVals[ind] ^ newVals[(ind + 1) % nParts];
    }
}


/// print hexadecimal representation of val
static void printHex(HashType* val)
{
    unsigned char* c = val->bytes;
    for (int i = sizeof(HashType) - 1; i >= 0; i--) {
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



