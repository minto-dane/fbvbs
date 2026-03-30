#include "fbvbs_asm.h"
#include "fbvbs_hypervisor.h"

/* Predicate for valid SHA-384 context state */
/*@
  @ predicate fbvbs_sha384_context_valid(struct fbvbs_sha384_context *c) =
  @     c != NULL &&
  @     (!c->invalid ==> c->buffered_length <= 127) &&
  @     (c->invalid ==> c->total_length == 0 && c->buffered_length == 0);
  @*/

void fbvbs_zero_memory(void *buffer, size_t length) {
    size_t index;
#ifdef __FRAMAC__
    char *bytes;
#endif

    if (buffer == NULL || length == 0U) {
        return;
    }

#ifndef __FRAMAC__
    {
        volatile uint8_t *volatile_bytes = (volatile uint8_t *)buffer;
        for (index = 0; index < length; ++index) {
            volatile_bytes[index] = 0U;
        }
        __asm__ volatile("" : : : "memory");
    }
#else
    bytes = (char *)buffer;
    /*@
      @ loop invariant 0 <= index <= length;
      @ loop invariant \forall size_t i; i < index ==> bytes[i] == 0;
      @ loop assigns index, bytes[0 .. length - 1];
      @ loop variant length - index;
      @*/
    for (index = 0; index < length; ++index) {
        bytes[index] = 0;
    }
#endif

    /* Memory barrier to ensure all writes are visible */
#ifndef __FRAMAC__
    __asm__ volatile("mfence" : : : "memory");
#endif
}

void fbvbs_copy_memory(void *destination, const void *source, size_t length) {
    char *dest;
    const char *src;
    size_t index;

    if (destination == NULL || source == NULL || length == 0U) {
        return;
    }

    dest = (char *)destination;
    src = (const char *)source;

    /*@
      @ loop invariant 0 <= index <= length;
      @ loop invariant \forall size_t i; i < index ==> dest[i] == src[i];
      @ loop invariant \separated(dest + (0 .. length - 1), src + (0 .. length - 1));
      @ loop assigns index, dest[0 .. length - 1];
      @ loop variant length - index;
      @*/
    for (index = 0; index < length; ++index) {
        dest[index] = src[index];
    }

    /* Memory barrier to ensure all writes are visible */
#ifndef __FRAMAC__
    __asm__ volatile("mfence" : : : "memory");
#endif
}

int fbvbs_constant_time_equals(const void *a, const void *b, size_t length) {
    const char *va;
    const char *vb;
    size_t index;
    uint32_t accumulator = 0U;

    if (a == NULL || b == NULL || length == 0U) {
        return 0;
    }

    va = (const char *)a;
    vb = (const char *)b;

    /* Constant-time: always iterate all bytes.
       Prevents timing side-channel that could leak partial match length. */
    /*@
      @ loop invariant 0 <= index <= length;
      @ loop invariant accumulator == 0 <==> \forall size_t i; i < index ==>
      @     va[i] == vb[i];
      @ loop assigns index, accumulator;
      @ loop variant length - index;
      @*/
    for (index = 0; index < length; ++index) {
        accumulator |= (uint32_t)(((uint8_t)va[index]) ^ ((uint8_t)vb[index]));
    }

    /* Compiler barrier: prevent optimizer from short-circuiting */
    accumulator = fbvbs_asm_observe_u32(accumulator);

    return accumulator == 0U ? 1 : 0;
}

int fbvbs_memory_is_zero(const void *buffer, size_t length) {
    const char *bytes;
    size_t index;
    uint32_t accumulator = 0U;

    if (buffer == NULL || length == 0U) {
        return 0;
    }

    bytes = (const char *)buffer;

    /* Constant-time: always iterate all bytes to prevent
       timing side-channel leaking which byte is non-zero */
    /*@
      @ loop invariant 0 <= index <= length;
      @ loop invariant accumulator == 0 <==> \forall size_t i; i < index ==>
      @     bytes[i] == 0;
      @ loop assigns index, accumulator;
      @ loop variant length - index;
      @*/
    for (index = 0; index < length; ++index) {
        accumulator |= (uint32_t)((uint8_t)bytes[index]);
    }

    /* Compiler barrier: prevent optimizer from short-circuiting */
    accumulator = fbvbs_asm_observe_u32(accumulator);

    return accumulator == 0U ? 1 : 0;
}

#ifndef __FRAMAC__
/*@
  @ requires 0 < shift < 64;
  @ assigns \nothing;
  @*/
static uint64_t fbvbs_rotr64(uint64_t value, uint32_t shift) {
    return (value >> shift) | (value << (64U - shift));
}

/*@ requires \valid_read(bytes + (0 .. 7));
  @ assigns \nothing;
  @*/
static uint64_t fbvbs_load_be64(const uint8_t bytes[8]) {
    return ((uint64_t)bytes[0] << 56) |
           ((uint64_t)bytes[1] << 48) |
           ((uint64_t)bytes[2] << 40) |
           ((uint64_t)bytes[3] << 32) |
           ((uint64_t)bytes[4] << 24) |
           ((uint64_t)bytes[5] << 16) |
           ((uint64_t)bytes[6] << 8) |
           (uint64_t)bytes[7];
}

/*@ requires \valid(bytes + (0 .. 7));
  @ assigns bytes[0 .. 7];
  @*/
static void fbvbs_store_be64(uint8_t bytes[8], uint64_t value) {
    bytes[0] = (uint8_t)(value >> 56);
    bytes[1] = (uint8_t)(value >> 48);
    bytes[2] = (uint8_t)(value >> 40);
    bytes[3] = (uint8_t)(value >> 32);
    bytes[4] = (uint8_t)(value >> 24);
    bytes[5] = (uint8_t)(value >> 16);
    bytes[6] = (uint8_t)(value >> 8);
    bytes[7] = (uint8_t)value;
}

/*@ requires \valid(state + (0 .. 7));
  @ requires \valid_read(block + (0 .. 127));
  @ assigns state[0 .. 7];
  @*/
static void fbvbs_sha384_process_block(uint64_t state[8], const uint8_t block[128]) {
    static const uint64_t k[80] = {
        UINT64_C(0x428A2F98D728AE22), UINT64_C(0x7137449123EF65CD),
        UINT64_C(0xB5C0FBCFEC4D3B2F), UINT64_C(0xE9B5DBA58189DBBC),
        UINT64_C(0x3956C25BF348B538), UINT64_C(0x59F111F1B605D019),
        UINT64_C(0x923F82A4AF194F9B), UINT64_C(0xAB1C5ED5DA6D8118),
        UINT64_C(0xD807AA98A3030242), UINT64_C(0x12835B0145706FBE),
        UINT64_C(0x243185BE4EE4B28C), UINT64_C(0x550C7DC3D5FFB4E2),
        UINT64_C(0x72BE5D74F27B896F), UINT64_C(0x80DEB1FE3B1696B1),
        UINT64_C(0x9BDC06A725C71235), UINT64_C(0xC19BF174CF692694),
        UINT64_C(0xE49B69C19EF14AD2), UINT64_C(0xEFBE4786384F25E3),
        UINT64_C(0x0FC19DC68B8CD5B5), UINT64_C(0x240CA1CC77AC9C65),
        UINT64_C(0x2DE92C6F592B0275), UINT64_C(0x4A7484AA6EA6E483),
        UINT64_C(0x5CB0A9DCBD41FBD4), UINT64_C(0x76F988DA831153B5),
        UINT64_C(0x983E5152EE66DFAB), UINT64_C(0xA831C66D2DB43210),
        UINT64_C(0xB00327C898FB213F), UINT64_C(0xBF597FC7BEEF0EE4),
        UINT64_C(0xC6E00BF33DA88FC2), UINT64_C(0xD5A79147930AA725),
        UINT64_C(0x06CA6351E003826F), UINT64_C(0x142929670A0E6E70),
        UINT64_C(0x27B70A8546D22FFC), UINT64_C(0x2E1B21385C26C926),
        UINT64_C(0x4D2C6DFC5AC42AED), UINT64_C(0x53380D139D95B3DF),
        UINT64_C(0x650A73548BAF63DE), UINT64_C(0x766A0ABB3C77B2A8),
        UINT64_C(0x81C2C92E47EDAEE6), UINT64_C(0x92722C851482353B),
        UINT64_C(0xA2BFE8A14CF10364), UINT64_C(0xA81A664BBC423001),
        UINT64_C(0xC24B8B70D0F89791), UINT64_C(0xC76C51A30654BE30),
        UINT64_C(0xD192E819D6EF5218), UINT64_C(0xD69906245565A910),
        UINT64_C(0xF40E35855771202A), UINT64_C(0x106AA07032BBD1B8),
        UINT64_C(0x19A4C116B8D2D0C8), UINT64_C(0x1E376C085141AB53),
        UINT64_C(0x2748774CDF8EEB99), UINT64_C(0x34B0BCB5E19B48A8),
        UINT64_C(0x391C0CB3C5C95A63), UINT64_C(0x4ED8AA4AE3418ACB),
        UINT64_C(0x5B9CCA4F7763E373), UINT64_C(0x682E6FF3D6B2B8A3),
        UINT64_C(0x748F82EE5DEFB2FC), UINT64_C(0x78A5636F43172F60),
        UINT64_C(0x84C87814A1F0AB72), UINT64_C(0x8CC702081A6439EC),
        UINT64_C(0x90BEFFFA23631E28), UINT64_C(0xA4506CEBDE82BDE9),
        UINT64_C(0xBEF9A3F7B2C67915), UINT64_C(0xC67178F2E372532B),
        UINT64_C(0xCA273ECEEA26619C), UINT64_C(0xD186B8C721C0C207),
        UINT64_C(0xEADA7DD6CDE0EB1E), UINT64_C(0xF57D4F7FEE6ED178),
        UINT64_C(0x06F067AA72176FBA), UINT64_C(0x0A637DC5A2C898A6),
        UINT64_C(0x113F9804BEF90DAE), UINT64_C(0x1B710B35131C471B),
        UINT64_C(0x28DB77F523047D84), UINT64_C(0x32CAAB7B40C72493),
        UINT64_C(0x3C9EBE0A15C9BEBC), UINT64_C(0x431D67C49C100D4C),
        UINT64_C(0x4CC5D4BECB3E42B6), UINT64_C(0x597F299CFC657E2A),
        UINT64_C(0x5FCB6FAB3AD6FAEC), UINT64_C(0x6C44198C4A475817)
    };
    uint64_t w[80] = {0};
    uint64_t a;
    uint64_t b;
    uint64_t c;
    uint64_t d;
    uint64_t e;
    uint64_t f;
    uint64_t g;
    uint64_t h;
    uint32_t index;

    for (index = 0U; index < 16U; ++index) {
        w[index] = fbvbs_load_be64(&block[index * 8U]);
    }
    for (index = 16U; index < 80U; ++index) {
        uint64_t s0 = fbvbs_rotr64(w[index - 15U], 1U) ^
                      fbvbs_rotr64(w[index - 15U], 8U) ^
                      (w[index - 15U] >> 7U);
        uint64_t s1 = fbvbs_rotr64(w[index - 2U], 19U) ^
                      fbvbs_rotr64(w[index - 2U], 61U) ^
                      (w[index - 2U] >> 6U);

        w[index] = w[index - 16U] + s0 + w[index - 7U] + s1;
    }

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    for (index = 0U; index < 80U; ++index) {
        uint64_t sum1 = fbvbs_rotr64(e, 14U) ^ fbvbs_rotr64(e, 18U) ^ fbvbs_rotr64(e, 41U);
        uint64_t ch = (e & f) ^ ((~e) & g);
        uint64_t temp1 = h + sum1 + ch + k[index] + w[index];
        uint64_t sum0 = fbvbs_rotr64(a, 28U) ^ fbvbs_rotr64(a, 34U) ^ fbvbs_rotr64(a, 39U);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t temp2 = sum0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

static const uint64_t fbvbs_sha384_initial_state[8] = {
    UINT64_C(0xCBBB9D5DC1059ED8), UINT64_C(0x629A292A367CD507),
    UINT64_C(0x9159015A3070DD17), UINT64_C(0x152FECD8F70E5939),
    UINT64_C(0x67332667FFC00B31), UINT64_C(0x8EB44A8768581511),
    UINT64_C(0xDB0C2E0D64F98FA7), UINT64_C(0x47B5481DBEFA4FA4)
};

/*@
  @ requires context != NULL;
  @ assigns *context;
  @ ensures fbvbs_sha384_context_valid(context);
  @ ensures context->total_length == 0;
  @ ensures context->buffered_length == 0;
  @ ensures context->invalid == 0;
  @*/
void fbvbs_sha384_init(struct fbvbs_sha384_context *context) {
    uint32_t index;

    if (context == NULL) {
        return;
    }

    *context = (struct fbvbs_sha384_context){0};
    for (index = 0U; index < 8U; ++index) {
        context->state[index] = fbvbs_sha384_initial_state[index];
    }
}

/*@
  @ requires fbvbs_sha384_context_valid(context);
  @ requires !context->invalid && length > 0 ==> data != NULL;
  @ requires !context->invalid && length > 0 ==> \valid_read(((const char*)data) + (0 .. length - 1));
  @ requires !context->invalid && length > 0 ==>
  @     \separated((const char*)data + (0 .. length - 1),
  @                (char*)context + (0 .. sizeof(*context) - 1));
  @ assigns *context;
  @ ensures fbvbs_sha384_context_valid(context);
  @ ensures context->invalid ==> context->total_length == 0 && context->buffered_length == 0;
  @*/
void fbvbs_sha384_update(
    struct fbvbs_sha384_context *context,
    const void *data,
    uint64_t length
) {
    const uint8_t *bytes;
    uint64_t remaining;
    uint32_t buffered;

    if (context == NULL) {
        return;
    }
    if (context->invalid) {
        return;
    }
    if (length == 0U) {
        return;
    }
    if (data == NULL || context->total_length > UINT64_MAX - length) {
        fbvbs_zero_memory(context->state, sizeof(context->state));
        fbvbs_zero_memory(context->buffer, sizeof(context->buffer));
        context->total_length = 0;
        context->buffered_length = 0;
        context->invalid = 1;
        return;
    }

    bytes = (const uint8_t *)data;
    remaining = length;
    buffered = context->buffered_length;

    if (buffered != 0U) {
        uint32_t needed = 128U - buffered;

        if (remaining < needed) {
            fbvbs_copy_memory(&context->buffer[buffered], bytes, (size_t)remaining);
            context->buffered_length += (uint32_t)remaining;
            context->total_length += length;
            return;
        }

        fbvbs_copy_memory(&context->buffer[buffered], bytes, (size_t)needed);
        fbvbs_sha384_process_block(context->state, context->buffer);
        bytes += needed;
        remaining -= needed;
        context->buffered_length = 0U;
    }

    while (remaining >= 128U) {
        fbvbs_sha384_process_block(context->state, bytes);
        bytes += 128U;
        remaining -= 128U;
    }

    if (remaining != 0U) {
        fbvbs_copy_memory(context->buffer, bytes, (size_t)remaining);
        context->buffered_length = (uint32_t)remaining;
    }

    context->total_length += length;
}

/*@
  @ requires fbvbs_sha384_context_valid(context);
  @ requires out != NULL;
  @ requires \valid(((char*)out) + (0 .. 47));
  @ requires \separated((char*)out + (0 .. 47),
  @                     (char*)context + (0 .. sizeof(*context) - 1));
  @ assigns ((char*)out)[0 .. 47];
  @ assigns *context;
  @ ensures \old(context->invalid) ==> \forall size_t i; i < 48 ==> out[i] == 0;
  @*/
void fbvbs_sha384_final(
    struct fbvbs_sha384_context *context,
    uint8_t out[48]
) {
    uint8_t final_block[256];
    uint64_t remainder;
    uint64_t bit_len_hi;
    uint64_t bit_len_lo;
    uint32_t out_index;

    if (context == NULL || out == NULL) {
        return;
    }

    if (context->invalid) {
        fbvbs_zero_memory(out, 48U);
        fbvbs_zero_memory(context, sizeof(*context));
        return;
    }

    remainder = context->buffered_length;

    fbvbs_zero_memory(final_block, sizeof(final_block));
    if (remainder != 0U) {
        fbvbs_copy_memory(final_block, context->buffer, (size_t)remainder);
    }
    final_block[remainder] = 0x80U;

    bit_len_hi = context->total_length >> 61U;
    bit_len_lo = context->total_length << 3U;

    if (remainder >= 112U) {
        fbvbs_sha384_process_block(context->state, final_block);
        fbvbs_zero_memory(final_block, 128U);
    }

    fbvbs_store_be64(&final_block[112], bit_len_hi);
    fbvbs_store_be64(&final_block[120], bit_len_lo);
    fbvbs_sha384_process_block(context->state, final_block);

    for (out_index = 0U; out_index < 6U; ++out_index) {
        fbvbs_store_be64(&out[out_index * 8U], context->state[out_index]);
    }

    fbvbs_zero_memory(final_block, sizeof(final_block));
    fbvbs_zero_memory(context, sizeof(*context));
}

void fbvbs_sha384(const void *data, uint64_t length, uint8_t out[48]) {
    struct fbvbs_sha384_context context;

    if (out == NULL) {
        return;
    }

    if (data == NULL && length != 0U) {
        fbvbs_zero_memory(out, 48U);
        return;
    }

    fbvbs_sha384_init(&context);
    fbvbs_sha384_update(&context, data, length);
    fbvbs_sha384_final(&context, out);
}
#else
void fbvbs_sha384_init(struct fbvbs_sha384_context *context) {
    if (context == NULL) {
        return;
    }
    *context = (struct fbvbs_sha384_context){0};
}

void fbvbs_sha384_update(
    struct fbvbs_sha384_context *context,
    const void *data,
    uint64_t length
) {
    if (context == NULL) {
        return;
    }
    if (data == NULL && length != 0U) {
        *context = (struct fbvbs_sha384_context){0};
        context->invalid = 1U;
        return;
    }
    if (context->total_length > UINT64_MAX - length) {
        *context = (struct fbvbs_sha384_context){0};
        context->invalid = 1U;
        return;
    }
    if (!context->invalid) {
        context->total_length += length;
        context->buffered_length = 0U;
    }
}

void fbvbs_sha384_final(
    struct fbvbs_sha384_context *context,
    uint8_t out[48]
) {
    uint32_t index;

    if (context == NULL || out == NULL) {
        return;
    }
    /*@ loop invariant 0 <= index <= 48U;
        loop assigns index, out[0 .. 47];
        loop variant 48U - index;
    */
    for (index = 0U; index < 48U; ++index) {
        out[index] = 0U;
    }
    *context = (struct fbvbs_sha384_context){0};
}

void fbvbs_sha384(const void *data, uint64_t length, uint8_t out[48]) {
    struct fbvbs_sha384_context context;

    if (out == NULL) {
        return;
    }
    fbvbs_sha384_init(&context);
    fbvbs_sha384_update(&context, data, length);
    fbvbs_sha384_final(&context, out);
}
#endif

/* Zero a 4096-byte page at the given guest physical address.
 * Retained-C bare metal treats guest physical pages as identity-mapped. */
void fbvbs_zero_page_at_gpa(uint64_t gpa) {
    if ((gpa & (FBVBS_PAGE_SIZE - 1U)) != 0U || gpa == 0U) {
        return;
    }

#ifndef __FRAMAC__
    fbvbs_zero_memory((void *)(uintptr_t)gpa, FBVBS_PAGE_SIZE);
#endif
}
