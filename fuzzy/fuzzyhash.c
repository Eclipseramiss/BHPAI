#include "fuzzyhash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define ALPHABET "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// ─────────────────────────────────────────────────────────────────────────────
// FNV-1a 64-bit
// ─────────────────────────────────────────────────────────────────────────────
static uint64_t fnv1a_64(const uint8_t* data, size_t len) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

// ─────────────────────────────────────────────────────────────────────────────
// Rolling FNV-1a
// ─────────────────────────────────────────────────────────────────────────────
typedef struct {
    uint64_t hash;
    uint64_t pow;           // precomputed WINDOW_SIZE-1 multiplications
    uint8_t  window[WINDOW_SIZE];
} RollingFNV;

static void rolling_init(RollingFNV* rf, const uint8_t* initial) {
    rf->hash = 0xcbf29ce484222325ULL;
    rf->pow  = 1;

    for (int i = 0; i < WINDOW_SIZE; i++) {
        rf->window[i] = initial[i];
        rf->hash ^= initial[i];
        rf->hash *= 0x100000001b3ULL;
        if (i < WINDOW_SIZE - 1) rf->pow *= 0x100000001b3ULL;
    }
}

static void rolling_update(RollingFNV* rf, uint8_t out, uint8_t in) {
    rf->hash ^= (uint64_t)out * rf->pow;
    rf->hash *= 0x100000001b3ULL;
    rf->hash ^= in;
}

static void hash_to_string(uint64_t val, char* out, size_t max_len) {
    int i = 0;
    if (val == 0) {
        out[0] = ALPHABET[0]; out[1] = '\0';
        return;
    }
    while (val > 0 && i < (int)max_len - 1) {
        out[i++] = ALPHABET[val & 63];
        val >>= 6;
    }
    out[i] = '\0';

    if (i < 3) {
        memmove(out + 3 - i, out, i + 1);
        memset(out, ALPHABET[0], 3 - i);
    }
}

static int levenshtein_weighted(const char* s1, const char* s2) {
    int len1 = strlen(s1);
    int len2 = strlen(s2);

    if (len1 == 0) return len2 * 6;
    if (len2 == 0) return len1 * 6;

    int* prev = calloc(len2 + 1, sizeof(int));
    int* curr = calloc(len2 + 1, sizeof(int));

    for (int j = 0; j <= len2; j++) prev[j] = j * 6;

    for (int i = 1; i <= len1; i++) {
        curr[0] = i * 6;
        for (int j = 1; j <= len2; j++) {
            int cost = (s1[i-1] == s2[j-1]) ? 0 : 5;
            int del  = prev[j]   + 6;
            int ins  = curr[j-1] + 6;
            int sub  = prev[j-1] + cost;
            curr[j] = del < ins ? (del < sub ? del : sub) : (ins < sub ? ins : sub);
        }
        int* tmp = prev; prev = curr; curr = tmp;
    }

    int dist = prev[len2];
    free(prev);
    free(curr);
    return dist;
}

// ─────────────────────────────────────────────────────────────────────────────
// Core fuzzy hash computation
// ─────────────────────────────────────────────────────────────────────────────
int compute_fuzzy_hash(const uint8_t* data, size_t size, FuzzyHash* fh) {
    if (!data || size == 0 || !fh) return -1;

    memset(fh, 0, sizeof(*fh));

    if (size < WINDOW_SIZE) {
        hash_to_string(fnv1a_64(data, size), fh->hash1, PIECE_HASH_LEN);
        strcpy(fh->hash2, fh->hash1);
        fh->block_size = 3;
        return 1;
    }

    int block_size = 3;
    while (block_size * MAX_PIECES < (int)size / 4) {
        block_size *= 2;
    }

    int b1 = block_size;
    int b2 = block_size * 2;

    char pieces1[MAX_PIECES][PIECE_HASH_LEN] = {{0}};
    char pieces2[MAX_PIECES][PIECE_HASH_LEN] = {{0}};
    int count1 = 0, count2 = 0;

    size_t pos = WINDOW_SIZE;
    size_t start1 = 0, start2 = 0;

    RollingFNV rf;
    rolling_init(&rf, data);

    while (pos < size) {
        uint64_t rh = rf.hash;

        if ((rh % b1) == (b1 - 1UL)) {
            size_t len = pos - start1;
            if (len > 0 && count1 < MAX_PIECES) {
                hash_to_string(fnv1a_64(data + start1, len), pieces1[count1++], PIECE_HASH_LEN);
            }
            start1 = pos;
        }

        if ((rh % b2) == (b2 - 1UL)) {
            size_t len = pos - start2;
            if (len > 0 && count2 < MAX_PIECES) {
                hash_to_string(fnv1a_64(data + start2, len), pieces2[count2++], PIECE_HASH_LEN);
            }
            start2 = pos;
        }

        rolling_update(&rf, data[pos - WINDOW_SIZE], data[pos]);
        pos++;
    }

    if (pos > start1 && count1 < MAX_PIECES) {
        hash_to_string(fnv1a_64(data + start1, pos - start1), pieces1[count1++], PIECE_HASH_LEN);
    }
    if (pos > start2 && count2 < MAX_PIECES) {
        hash_to_string(fnv1a_64(data + start2, pos - start2), pieces2[count2++], PIECE_HASH_LEN);
    }

    fh->block_size = b1;

    for (int i = 0; i < count1; i++)
        strncat(fh->hash1, pieces1[i], PIECE_HASH_LEN - strlen(fh->hash1) - 1);

    for (int i = 0; i < count2; i++)
        strncat(fh->hash2, pieces2[i], PIECE_HASH_LEN - strlen(fh->hash2) - 1);

    return count1 + count2;
}

int fuzzy_similarity(const FuzzyHash* a, const FuzzyHash* b) {
    if (!a || !b) return 0;

    if (abs(a->block_size - b->block_size) > a->block_size / 2 + 4)
        return 0;

    int d1 = levenshtein_weighted(a->hash1, b->hash1);
    int d2 = levenshtein_weighted(a->hash2, b->hash2);

    int len1a = strlen(a->hash1), len1b = strlen(b->hash1);
    int len2a = strlen(a->hash2), len2b = strlen(b->hash2);

    int max1 = len1a > len1b ? len1a : len1b;
    int max2 = len2a > len2b ? len2a : len2b;

    if (max1 == 0 || max2 == 0) return 0;

    int score1 = 100 - (d1 * 100 / (max1 * 6 + 1));
    int score2 = 100 - (d2 * 100 / (max2 * 6 + 1));

    int final = (score1 * 35 + score2 * 65) / 100;

    if (abs(a->block_size - b->block_size) <= 4)
        final = final * 11 / 10;

    if (final > 100) final = 100;
    if (final < 0) final = 0;

    return final;
}

uint8_t* read_file(const char* path, size_t* out_size) {
    if (!path || !out_size) return NULL;

    FILE* f = fopen(path, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz <= 0) {
        fclose(f);
        return NULL;
    }

    uint8_t* buf = malloc((size_t)sz);
    if (!buf) {
        fclose(f);
        return NULL;
    }

    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return NULL;
    }

    fclose(f);
    *out_size = (size_t)sz;
    return buf;
}

int fuzzyhash_to_string(const FuzzyHash* fh, char* buf, size_t bufsize) {
    if (!fh || !buf || bufsize < 16) return -1;

    return snprintf(buf, bufsize, "%d:%s:%s",
                    fh->block_size,
                    fh->hash1[0] ? fh->hash1 : "EMPTY",
                    fh->hash2[0] ? fh->hash2 : "EMPTY");
}