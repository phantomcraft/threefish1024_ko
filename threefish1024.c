/*
	Threefish1024 block cipher kernel module.
	v0.2

    Threefish1024 is a modified version of original Threefish512 from
    https://github.com/bogdankernel/threefish_512

    Functions threefish_encrypt_1024 and threefish_decrypt_1024
    are based on last version of skein hash staging driver:
    https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/drivers/staging/skein/threefish_block.c?h=linux-4.17.y

    That project was removed when Linux jumped from version 4.17.x to
    4.18+.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/crypto.h>
#include <linux/bitops.h>
#include <crypto/algapi.h>

#define  SKEIN_MAX_STATE_WORDS (16)  // in threefish_512 was 8, now it's 16 for 1024 bits version.
#define KeyScheduleConst 0x1BD11BDAA9FC1A22ULL

struct threefish_key {
	//u64 state_size;
	u64 key[SKEIN_MAX_STATE_WORDS+1];   /* max number of key words*/
	//u64 tweak[3];
};

static void threefishSetKey1024(struct threefish_key* keyCtx, u64* keyData)
{
    int i;
    u64 parity = KeyScheduleConst;

    for (i = 0; i != (1024/64); ++i) {
        keyCtx->key[i] = le64_to_cpu(keyData[i]);
        parity ^= le64_to_cpu(keyData[i]);
    }
    keyCtx->key[i] = parity;
}

/* This 64-bit tweak word is empty and the others are filled with the IV
value. Only t0 and t2 are summed because there is more mixing operations
between them than t0,t1 or t1,t2; this come closer to the Threefish
standart which uses 128-bit tweak for purposes other than disk
encryption.

A random hexadecimal value can be added in the place of zeros and so
will be processed by cipher like t0 and t2, but this will turn the 
module incompatible with block devices encrypted with other tweak
values.

Adding a custom tweak will not add bits of security to THIS Threefish 
implementation, it will just make the block mixing stronger.

\\
*/
#define t1 0x0000000000000000ULL

#define t2 t0

/*
In the two functions bellow, tweak keys are replaced by an IV counter,
pass plain64 mode as IV to deal with Hard Disks with more than 2TB. 
Threefish doesn't need random IVs/counters, use plain IV like XTS mode
does.

Tweak keys doesn't add bits of security to its 1024 bits key size in 
THIS Threefish implementation.

*/

void threefish_encrypt_1024(const struct threefish_key *key_ctx, const u64 *input,
			   u64 *output, u64 t0)
// Taken from: 
// https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/drivers/staging/skein/threefish_block.c?h=linux-4.17.y#n3325
{
	u64 b0 = le64_to_cpu(input[0]), b1 = le64_to_cpu(input[1]),
	    b2 = le64_to_cpu(input[2]), b3 = le64_to_cpu(input[3]),
	    b4 = le64_to_cpu(input[4]), b5 = le64_to_cpu(input[5]),
	    b6 = le64_to_cpu(input[6]), b7 = le64_to_cpu(input[7]),
	    b8 = le64_to_cpu(input[8]), b9 = le64_to_cpu(input[9]),
	    b10 = le64_to_cpu(input[10]), b11 = le64_to_cpu(input[11]),
	    b12 = le64_to_cpu(input[12]), b13 = le64_to_cpu(input[13]),
	    b14 = le64_to_cpu(input[14]), b15 = le64_to_cpu(input[15]);
	u64 k0 = key_ctx->key[0], k1 = key_ctx->key[1],
	    k2 = key_ctx->key[2], k3 = key_ctx->key[3],
	    k4 = key_ctx->key[4], k5 = key_ctx->key[5],
	    k6 = key_ctx->key[6], k7 = key_ctx->key[7],
	    k8 = key_ctx->key[8], k9 = key_ctx->key[9],
	    k10 = key_ctx->key[10], k11 = key_ctx->key[11],
	    k12 = key_ctx->key[12], k13 = key_ctx->key[13],
	    k14 = key_ctx->key[14], k15 = key_ctx->key[15],
	    k16 = key_ctx->key[16];
	//u64 t0 = key_ctx->tweak[0], t1 = key_ctx->tweak[1],
	//    t2 = key_ctx->tweak[2];

	b1 += k1;
	b0 += b1 + k0;
	b1 = rol64(b1, 24) ^ b0;

	b3 += k3;
	b2 += b3 + k2;
	b3 = rol64(b3, 13) ^ b2;

	b5 += k5;
	b4 += b5 + k4;
	b5 = rol64(b5, 8) ^ b4;

	b7 += k7;
	b6 += b7 + k6;
	b7 = rol64(b7, 47) ^ b6;

	b9 += k9;
	b8 += b9 + k8;
	b9 = rol64(b9, 8) ^ b8;

	b11 += k11;
	b10 += b11 + k10;
	b11 = rol64(b11, 17) ^ b10;

	b13 += k13 + t0;
	b12 += b13 + k12;
	b13 = rol64(b13, 22) ^ b12;

	b15 += k15;
	b14 += b15 + k14 + t1;
	b15 = rol64(b15, 37) ^ b14;

	b0 += b9;
	b9 = rol64(b9, 38) ^ b0;

	b2 += b13;
	b13 = rol64(b13, 19) ^ b2;

	b6 += b11;
	b11 = rol64(b11, 10) ^ b6;

	b4 += b15;
	b15 = rol64(b15, 55) ^ b4;

	b10 += b7;
	b7 = rol64(b7, 49) ^ b10;

	b12 += b3;
	b3 = rol64(b3, 18) ^ b12;

	b14 += b5;
	b5 = rol64(b5, 23) ^ b14;

	b8 += b1;
	b1 = rol64(b1, 52) ^ b8;

	b0 += b7;
	b7 = rol64(b7, 33) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 4) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 51) ^ b4;

	b6 += b1;
	b1 = rol64(b1, 13) ^ b6;

	b12 += b15;
	b15 = rol64(b15, 34) ^ b12;

	b14 += b13;
	b13 = rol64(b13, 41) ^ b14;

	b8 += b11;
	b11 = rol64(b11, 59) ^ b8;

	b10 += b9;
	b9 = rol64(b9, 17) ^ b10;

	b0 += b15;
	b15 = rol64(b15, 5) ^ b0;

	b2 += b11;
	b11 = rol64(b11, 20) ^ b2;

	b6 += b13;
	b13 = rol64(b13, 48) ^ b6;

	b4 += b9;
	b9 = rol64(b9, 41) ^ b4;

	b14 += b1;
	b1 = rol64(b1, 47) ^ b14;

	b8 += b5;
	b5 = rol64(b5, 28) ^ b8;

	b10 += b3;
	b3 = rol64(b3, 16) ^ b10;

	b12 += b7;
	b7 = rol64(b7, 25) ^ b12;

	b1 += k2;
	b0 += b1 + k1;
	b1 = rol64(b1, 41) ^ b0;

	b3 += k4;
	b2 += b3 + k3;
	b3 = rol64(b3, 9) ^ b2;

	b5 += k6;
	b4 += b5 + k5;
	b5 = rol64(b5, 37) ^ b4;

	b7 += k8;
	b6 += b7 + k7;
	b7 = rol64(b7, 31) ^ b6;

	b9 += k10;
	b8 += b9 + k9;
	b9 = rol64(b9, 12) ^ b8;

	b11 += k12;
	b10 += b11 + k11;
	b11 = rol64(b11, 47) ^ b10;

	b13 += k14 + t1;
	b12 += b13 + k13;
	b13 = rol64(b13, 44) ^ b12;

	b15 += k16 + 1;
	b14 += b15 + k15 + t2;
	b15 = rol64(b15, 30) ^ b14;

	b0 += b9;
	b9 = rol64(b9, 16) ^ b0;

	b2 += b13;
	b13 = rol64(b13, 34) ^ b2;

	b6 += b11;
	b11 = rol64(b11, 56) ^ b6;

	b4 += b15;
	b15 = rol64(b15, 51) ^ b4;

	b10 += b7;
	b7 = rol64(b7, 4) ^ b10;

	b12 += b3;
	b3 = rol64(b3, 53) ^ b12;

	b14 += b5;
	b5 = rol64(b5, 42) ^ b14;

	b8 += b1;
	b1 = rol64(b1, 41) ^ b8;

	b0 += b7;
	b7 = rol64(b7, 31) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 44) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 47) ^ b4;

	b6 += b1;
	b1 = rol64(b1, 46) ^ b6;

	b12 += b15;
	b15 = rol64(b15, 19) ^ b12;

	b14 += b13;
	b13 = rol64(b13, 42) ^ b14;

	b8 += b11;
	b11 = rol64(b11, 44) ^ b8;

	b10 += b9;
	b9 = rol64(b9, 25) ^ b10;

	b0 += b15;
	b15 = rol64(b15, 9) ^ b0;

	b2 += b11;
	b11 = rol64(b11, 48) ^ b2;

	b6 += b13;
	b13 = rol64(b13, 35) ^ b6;

	b4 += b9;
	b9 = rol64(b9, 52) ^ b4;

	b14 += b1;
	b1 = rol64(b1, 23) ^ b14;

	b8 += b5;
	b5 = rol64(b5, 31) ^ b8;

	b10 += b3;
	b3 = rol64(b3, 37) ^ b10;

	b12 += b7;
	b7 = rol64(b7, 20) ^ b12;

	b1 += k3;
	b0 += b1 + k2;
	b1 = rol64(b1, 24) ^ b0;

	b3 += k5;
	b2 += b3 + k4;
	b3 = rol64(b3, 13) ^ b2;

	b5 += k7;
	b4 += b5 + k6;
	b5 = rol64(b5, 8) ^ b4;

	b7 += k9;
	b6 += b7 + k8;
	b7 = rol64(b7, 47) ^ b6;

	b9 += k11;
	b8 += b9 + k10;
	b9 = rol64(b9, 8) ^ b8;

	b11 += k13;
	b10 += b11 + k12;
	b11 = rol64(b11, 17) ^ b10;

	b13 += k15 + t2;
	b12 += b13 + k14;
	b13 = rol64(b13, 22) ^ b12;

	b15 += k0 + 2;
	b14 += b15 + k16 + t0;
	b15 = rol64(b15, 37) ^ b14;

	b0 += b9;
	b9 = rol64(b9, 38) ^ b0;

	b2 += b13;
	b13 = rol64(b13, 19) ^ b2;

	b6 += b11;
	b11 = rol64(b11, 10) ^ b6;

	b4 += b15;
	b15 = rol64(b15, 55) ^ b4;

	b10 += b7;
	b7 = rol64(b7, 49) ^ b10;

	b12 += b3;
	b3 = rol64(b3, 18) ^ b12;

	b14 += b5;
	b5 = rol64(b5, 23) ^ b14;

	b8 += b1;
	b1 = rol64(b1, 52) ^ b8;

	b0 += b7;
	b7 = rol64(b7, 33) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 4) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 51) ^ b4;

	b6 += b1;
	b1 = rol64(b1, 13) ^ b6;

	b12 += b15;
	b15 = rol64(b15, 34) ^ b12;

	b14 += b13;
	b13 = rol64(b13, 41) ^ b14;

	b8 += b11;
	b11 = rol64(b11, 59) ^ b8;

	b10 += b9;
	b9 = rol64(b9, 17) ^ b10;

	b0 += b15;
	b15 = rol64(b15, 5) ^ b0;

	b2 += b11;
	b11 = rol64(b11, 20) ^ b2;

	b6 += b13;
	b13 = rol64(b13, 48) ^ b6;

	b4 += b9;
	b9 = rol64(b9, 41) ^ b4;

	b14 += b1;
	b1 = rol64(b1, 47) ^ b14;

	b8 += b5;
	b5 = rol64(b5, 28) ^ b8;

	b10 += b3;
	b3 = rol64(b3, 16) ^ b10;

	b12 += b7;
	b7 = rol64(b7, 25) ^ b12;

	b1 += k4;
	b0 += b1 + k3;
	b1 = rol64(b1, 41) ^ b0;

	b3 += k6;
	b2 += b3 + k5;
	b3 = rol64(b3, 9) ^ b2;

	b5 += k8;
	b4 += b5 + k7;
	b5 = rol64(b5, 37) ^ b4;

	b7 += k10;
	b6 += b7 + k9;
	b7 = rol64(b7, 31) ^ b6;

	b9 += k12;
	b8 += b9 + k11;
	b9 = rol64(b9, 12) ^ b8;

	b11 += k14;
	b10 += b11 + k13;
	b11 = rol64(b11, 47) ^ b10;

	b13 += k16 + t0;
	b12 += b13 + k15;
	b13 = rol64(b13, 44) ^ b12;

	b15 += k1 + 3;
	b14 += b15 + k0 + t1;
	b15 = rol64(b15, 30) ^ b14;

	b0 += b9;
	b9 = rol64(b9, 16) ^ b0;

	b2 += b13;
	b13 = rol64(b13, 34) ^ b2;

	b6 += b11;
	b11 = rol64(b11, 56) ^ b6;

	b4 += b15;
	b15 = rol64(b15, 51) ^ b4;

	b10 += b7;
	b7 = rol64(b7, 4) ^ b10;

	b12 += b3;
	b3 = rol64(b3, 53) ^ b12;

	b14 += b5;
	b5 = rol64(b5, 42) ^ b14;

	b8 += b1;
	b1 = rol64(b1, 41) ^ b8;

	b0 += b7;
	b7 = rol64(b7, 31) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 44) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 47) ^ b4;

	b6 += b1;
	b1 = rol64(b1, 46) ^ b6;

	b12 += b15;
	b15 = rol64(b15, 19) ^ b12;

	b14 += b13;
	b13 = rol64(b13, 42) ^ b14;

	b8 += b11;
	b11 = rol64(b11, 44) ^ b8;

	b10 += b9;
	b9 = rol64(b9, 25) ^ b10;

	b0 += b15;
	b15 = rol64(b15, 9) ^ b0;

	b2 += b11;
	b11 = rol64(b11, 48) ^ b2;

	b6 += b13;
	b13 = rol64(b13, 35) ^ b6;

	b4 += b9;
	b9 = rol64(b9, 52) ^ b4;

	b14 += b1;
	b1 = rol64(b1, 23) ^ b14;

	b8 += b5;
	b5 = rol64(b5, 31) ^ b8;

	b10 += b3;
	b3 = rol64(b3, 37) ^ b10;

	b12 += b7;
	b7 = rol64(b7, 20) ^ b12;

	b1 += k5;
	b0 += b1 + k4;
	b1 = rol64(b1, 24) ^ b0;

	b3 += k7;
	b2 += b3 + k6;
	b3 = rol64(b3, 13) ^ b2;

	b5 += k9;
	b4 += b5 + k8;
	b5 = rol64(b5, 8) ^ b4;

	b7 += k11;
	b6 += b7 + k10;
	b7 = rol64(b7, 47) ^ b6;

	b9 += k13;
	b8 += b9 + k12;
	b9 = rol64(b9, 8) ^ b8;

	b11 += k15;
	b10 += b11 + k14;
	b11 = rol64(b11, 17) ^ b10;

	b13 += k0 + t1;
	b12 += b13 + k16;
	b13 = rol64(b13, 22) ^ b12;

	b15 += k2 + 4;
	b14 += b15 + k1 + t2;
	b15 = rol64(b15, 37) ^ b14;

	b0 += b9;
	b9 = rol64(b9, 38) ^ b0;

	b2 += b13;
	b13 = rol64(b13, 19) ^ b2;

	b6 += b11;
	b11 = rol64(b11, 10) ^ b6;

	b4 += b15;
	b15 = rol64(b15, 55) ^ b4;

	b10 += b7;
	b7 = rol64(b7, 49) ^ b10;

	b12 += b3;
	b3 = rol64(b3, 18) ^ b12;

	b14 += b5;
	b5 = rol64(b5, 23) ^ b14;

	b8 += b1;
	b1 = rol64(b1, 52) ^ b8;

	b0 += b7;
	b7 = rol64(b7, 33) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 4) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 51) ^ b4;

	b6 += b1;
	b1 = rol64(b1, 13) ^ b6;

	b12 += b15;
	b15 = rol64(b15, 34) ^ b12;

	b14 += b13;
	b13 = rol64(b13, 41) ^ b14;

	b8 += b11;
	b11 = rol64(b11, 59) ^ b8;

	b10 += b9;
	b9 = rol64(b9, 17) ^ b10;

	b0 += b15;
	b15 = rol64(b15, 5) ^ b0;

	b2 += b11;
	b11 = rol64(b11, 20) ^ b2;

	b6 += b13;
	b13 = rol64(b13, 48) ^ b6;

	b4 += b9;
	b9 = rol64(b9, 41) ^ b4;

	b14 += b1;
	b1 = rol64(b1, 47) ^ b14;

	b8 += b5;
	b5 = rol64(b5, 28) ^ b8;

	b10 += b3;
	b3 = rol64(b3, 16) ^ b10;

	b12 += b7;
	b7 = rol64(b7, 25) ^ b12;

	b1 += k6;
	b0 += b1 + k5;
	b1 = rol64(b1, 41) ^ b0;

	b3 += k8;
	b2 += b3 + k7;
	b3 = rol64(b3, 9) ^ b2;

	b5 += k10;
	b4 += b5 + k9;
	b5 = rol64(b5, 37) ^ b4;

	b7 += k12;
	b6 += b7 + k11;
	b7 = rol64(b7, 31) ^ b6;

	b9 += k14;
	b8 += b9 + k13;
	b9 = rol64(b9, 12) ^ b8;

	b11 += k16;
	b10 += b11 + k15;
	b11 = rol64(b11, 47) ^ b10;

	b13 += k1 + t2;
	b12 += b13 + k0;
	b13 = rol64(b13, 44) ^ b12;

	b15 += k3 + 5;
	b14 += b15 + k2 + t0;
	b15 = rol64(b15, 30) ^ b14;

	b0 += b9;
	b9 = rol64(b9, 16) ^ b0;

	b2 += b13;
	b13 = rol64(b13, 34) ^ b2;

	b6 += b11;
	b11 = rol64(b11, 56) ^ b6;

	b4 += b15;
	b15 = rol64(b15, 51) ^ b4;

	b10 += b7;
	b7 = rol64(b7, 4) ^ b10;

	b12 += b3;
	b3 = rol64(b3, 53) ^ b12;

	b14 += b5;
	b5 = rol64(b5, 42) ^ b14;

	b8 += b1;
	b1 = rol64(b1, 41) ^ b8;

	b0 += b7;
	b7 = rol64(b7, 31) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 44) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 47) ^ b4;

	b6 += b1;
	b1 = rol64(b1, 46) ^ b6;

	b12 += b15;
	b15 = rol64(b15, 19) ^ b12;

	b14 += b13;
	b13 = rol64(b13, 42) ^ b14;

	b8 += b11;
	b11 = rol64(b11, 44) ^ b8;

	b10 += b9;
	b9 = rol64(b9, 25) ^ b10;

	b0 += b15;
	b15 = rol64(b15, 9) ^ b0;

	b2 += b11;
	b11 = rol64(b11, 48) ^ b2;

	b6 += b13;
	b13 = rol64(b13, 35) ^ b6;

	b4 += b9;
	b9 = rol64(b9, 52) ^ b4;

	b14 += b1;
	b1 = rol64(b1, 23) ^ b14;

	b8 += b5;
	b5 = rol64(b5, 31) ^ b8;

	b10 += b3;
	b3 = rol64(b3, 37) ^ b10;

	b12 += b7;
	b7 = rol64(b7, 20) ^ b12;

	b1 += k7;
	b0 += b1 + k6;
	b1 = rol64(b1, 24) ^ b0;

	b3 += k9;
	b2 += b3 + k8;
	b3 = rol64(b3, 13) ^ b2;

	b5 += k11;
	b4 += b5 + k10;
	b5 = rol64(b5, 8) ^ b4;

	b7 += k13;
	b6 += b7 + k12;
	b7 = rol64(b7, 47) ^ b6;

	b9 += k15;
	b8 += b9 + k14;
	b9 = rol64(b9, 8) ^ b8;

	b11 += k0;
	b10 += b11 + k16;
	b11 = rol64(b11, 17) ^ b10;

	b13 += k2 + t0;
	b12 += b13 + k1;
	b13 = rol64(b13, 22) ^ b12;

	b15 += k4 + 6;
	b14 += b15 + k3 + t1;
	b15 = rol64(b15, 37) ^ b14;

	b0 += b9;
	b9 = rol64(b9, 38) ^ b0;

	b2 += b13;
	b13 = rol64(b13, 19) ^ b2;

	b6 += b11;
	b11 = rol64(b11, 10) ^ b6;

	b4 += b15;
	b15 = rol64(b15, 55) ^ b4;

	b10 += b7;
	b7 = rol64(b7, 49) ^ b10;

	b12 += b3;
	b3 = rol64(b3, 18) ^ b12;

	b14 += b5;
	b5 = rol64(b5, 23) ^ b14;

	b8 += b1;
	b1 = rol64(b1, 52) ^ b8;

	b0 += b7;
	b7 = rol64(b7, 33) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 4) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 51) ^ b4;

	b6 += b1;
	b1 = rol64(b1, 13) ^ b6;

	b12 += b15;
	b15 = rol64(b15, 34) ^ b12;

	b14 += b13;
	b13 = rol64(b13, 41) ^ b14;

	b8 += b11;
	b11 = rol64(b11, 59) ^ b8;

	b10 += b9;
	b9 = rol64(b9, 17) ^ b10;

	b0 += b15;
	b15 = rol64(b15, 5) ^ b0;

	b2 += b11;
	b11 = rol64(b11, 20) ^ b2;

	b6 += b13;
	b13 = rol64(b13, 48) ^ b6;

	b4 += b9;
	b9 = rol64(b9, 41) ^ b4;

	b14 += b1;
	b1 = rol64(b1, 47) ^ b14;

	b8 += b5;
	b5 = rol64(b5, 28) ^ b8;

	b10 += b3;
	b3 = rol64(b3, 16) ^ b10;

	b12 += b7;
	b7 = rol64(b7, 25) ^ b12;

	b1 += k8;
	b0 += b1 + k7;
	b1 = rol64(b1, 41) ^ b0;

	b3 += k10;
	b2 += b3 + k9;
	b3 = rol64(b3, 9) ^ b2;

	b5 += k12;
	b4 += b5 + k11;
	b5 = rol64(b5, 37) ^ b4;

	b7 += k14;
	b6 += b7 + k13;
	b7 = rol64(b7, 31) ^ b6;

	b9 += k16;
	b8 += b9 + k15;
	b9 = rol64(b9, 12) ^ b8;

	b11 += k1;
	b10 += b11 + k0;
	b11 = rol64(b11, 47) ^ b10;

	b13 += k3 + t1;
	b12 += b13 + k2;
	b13 = rol64(b13, 44) ^ b12;

	b15 += k5 + 7;
	b14 += b15 + k4 + t2;
	b15 = rol64(b15, 30) ^ b14;

	b0 += b9;
	b9 = rol64(b9, 16) ^ b0;

	b2 += b13;
	b13 = rol64(b13, 34) ^ b2;

	b6 += b11;
	b11 = rol64(b11, 56) ^ b6;

	b4 += b15;
	b15 = rol64(b15, 51) ^ b4;

	b10 += b7;
	b7 = rol64(b7, 4) ^ b10;

	b12 += b3;
	b3 = rol64(b3, 53) ^ b12;

	b14 += b5;
	b5 = rol64(b5, 42) ^ b14;

	b8 += b1;
	b1 = rol64(b1, 41) ^ b8;

	b0 += b7;
	b7 = rol64(b7, 31) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 44) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 47) ^ b4;

	b6 += b1;
	b1 = rol64(b1, 46) ^ b6;

	b12 += b15;
	b15 = rol64(b15, 19) ^ b12;

	b14 += b13;
	b13 = rol64(b13, 42) ^ b14;

	b8 += b11;
	b11 = rol64(b11, 44) ^ b8;

	b10 += b9;
	b9 = rol64(b9, 25) ^ b10;

	b0 += b15;
	b15 = rol64(b15, 9) ^ b0;

	b2 += b11;
	b11 = rol64(b11, 48) ^ b2;

	b6 += b13;
	b13 = rol64(b13, 35) ^ b6;

	b4 += b9;
	b9 = rol64(b9, 52) ^ b4;

	b14 += b1;
	b1 = rol64(b1, 23) ^ b14;

	b8 += b5;
	b5 = rol64(b5, 31) ^ b8;

	b10 += b3;
	b3 = rol64(b3, 37) ^ b10;

	b12 += b7;
	b7 = rol64(b7, 20) ^ b12;

	b1 += k9;
	b0 += b1 + k8;
	b1 = rol64(b1, 24) ^ b0;

	b3 += k11;
	b2 += b3 + k10;
	b3 = rol64(b3, 13) ^ b2;

	b5 += k13;
	b4 += b5 + k12;
	b5 = rol64(b5, 8) ^ b4;

	b7 += k15;
	b6 += b7 + k14;
	b7 = rol64(b7, 47) ^ b6;

	b9 += k0;
	b8 += b9 + k16;
	b9 = rol64(b9, 8) ^ b8;

	b11 += k2;
	b10 += b11 + k1;
	b11 = rol64(b11, 17) ^ b10;

	b13 += k4 + t2;
	b12 += b13 + k3;
	b13 = rol64(b13, 22) ^ b12;

	b15 += k6 + 8;
	b14 += b15 + k5 + t0;
	b15 = rol64(b15, 37) ^ b14;

	b0 += b9;
	b9 = rol64(b9, 38) ^ b0;

	b2 += b13;
	b13 = rol64(b13, 19) ^ b2;

	b6 += b11;
	b11 = rol64(b11, 10) ^ b6;

	b4 += b15;
	b15 = rol64(b15, 55) ^ b4;

	b10 += b7;
	b7 = rol64(b7, 49) ^ b10;

	b12 += b3;
	b3 = rol64(b3, 18) ^ b12;

	b14 += b5;
	b5 = rol64(b5, 23) ^ b14;

	b8 += b1;
	b1 = rol64(b1, 52) ^ b8;

	b0 += b7;
	b7 = rol64(b7, 33) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 4) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 51) ^ b4;

	b6 += b1;
	b1 = rol64(b1, 13) ^ b6;

	b12 += b15;
	b15 = rol64(b15, 34) ^ b12;

	b14 += b13;
	b13 = rol64(b13, 41) ^ b14;

	b8 += b11;
	b11 = rol64(b11, 59) ^ b8;

	b10 += b9;
	b9 = rol64(b9, 17) ^ b10;

	b0 += b15;
	b15 = rol64(b15, 5) ^ b0;

	b2 += b11;
	b11 = rol64(b11, 20) ^ b2;

	b6 += b13;
	b13 = rol64(b13, 48) ^ b6;

	b4 += b9;
	b9 = rol64(b9, 41) ^ b4;

	b14 += b1;
	b1 = rol64(b1, 47) ^ b14;

	b8 += b5;
	b5 = rol64(b5, 28) ^ b8;

	b10 += b3;
	b3 = rol64(b3, 16) ^ b10;

	b12 += b7;
	b7 = rol64(b7, 25) ^ b12;

	b1 += k10;
	b0 += b1 + k9;
	b1 = rol64(b1, 41) ^ b0;

	b3 += k12;
	b2 += b3 + k11;
	b3 = rol64(b3, 9) ^ b2;

	b5 += k14;
	b4 += b5 + k13;
	b5 = rol64(b5, 37) ^ b4;

	b7 += k16;
	b6 += b7 + k15;
	b7 = rol64(b7, 31) ^ b6;

	b9 += k1;
	b8 += b9 + k0;
	b9 = rol64(b9, 12) ^ b8;

	b11 += k3;
	b10 += b11 + k2;
	b11 = rol64(b11, 47) ^ b10;

	b13 += k5 + t0;
	b12 += b13 + k4;
	b13 = rol64(b13, 44) ^ b12;

	b15 += k7 + 9;
	b14 += b15 + k6 + t1;
	b15 = rol64(b15, 30) ^ b14;

	b0 += b9;
	b9 = rol64(b9, 16) ^ b0;

	b2 += b13;
	b13 = rol64(b13, 34) ^ b2;

	b6 += b11;
	b11 = rol64(b11, 56) ^ b6;

	b4 += b15;
	b15 = rol64(b15, 51) ^ b4;

	b10 += b7;
	b7 = rol64(b7, 4) ^ b10;

	b12 += b3;
	b3 = rol64(b3, 53) ^ b12;

	b14 += b5;
	b5 = rol64(b5, 42) ^ b14;

	b8 += b1;
	b1 = rol64(b1, 41) ^ b8;

	b0 += b7;
	b7 = rol64(b7, 31) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 44) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 47) ^ b4;

	b6 += b1;
	b1 = rol64(b1, 46) ^ b6;

	b12 += b15;
	b15 = rol64(b15, 19) ^ b12;

	b14 += b13;
	b13 = rol64(b13, 42) ^ b14;

	b8 += b11;
	b11 = rol64(b11, 44) ^ b8;

	b10 += b9;
	b9 = rol64(b9, 25) ^ b10;

	b0 += b15;
	b15 = rol64(b15, 9) ^ b0;

	b2 += b11;
	b11 = rol64(b11, 48) ^ b2;

	b6 += b13;
	b13 = rol64(b13, 35) ^ b6;

	b4 += b9;
	b9 = rol64(b9, 52) ^ b4;

	b14 += b1;
	b1 = rol64(b1, 23) ^ b14;

	b8 += b5;
	b5 = rol64(b5, 31) ^ b8;

	b10 += b3;
	b3 = rol64(b3, 37) ^ b10;

	b12 += b7;
	b7 = rol64(b7, 20) ^ b12;

	b1 += k11;
	b0 += b1 + k10;
	b1 = rol64(b1, 24) ^ b0;

	b3 += k13;
	b2 += b3 + k12;
	b3 = rol64(b3, 13) ^ b2;

	b5 += k15;
	b4 += b5 + k14;
	b5 = rol64(b5, 8) ^ b4;

	b7 += k0;
	b6 += b7 + k16;
	b7 = rol64(b7, 47) ^ b6;

	b9 += k2;
	b8 += b9 + k1;
	b9 = rol64(b9, 8) ^ b8;

	b11 += k4;
	b10 += b11 + k3;
	b11 = rol64(b11, 17) ^ b10;

	b13 += k6 + t1;
	b12 += b13 + k5;
	b13 = rol64(b13, 22) ^ b12;

	b15 += k8 + 10;
	b14 += b15 + k7 + t2;
	b15 = rol64(b15, 37) ^ b14;

	b0 += b9;
	b9 = rol64(b9, 38) ^ b0;

	b2 += b13;
	b13 = rol64(b13, 19) ^ b2;

	b6 += b11;
	b11 = rol64(b11, 10) ^ b6;

	b4 += b15;
	b15 = rol64(b15, 55) ^ b4;

	b10 += b7;
	b7 = rol64(b7, 49) ^ b10;

	b12 += b3;
	b3 = rol64(b3, 18) ^ b12;

	b14 += b5;
	b5 = rol64(b5, 23) ^ b14;

	b8 += b1;
	b1 = rol64(b1, 52) ^ b8;

	b0 += b7;
	b7 = rol64(b7, 33) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 4) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 51) ^ b4;

	b6 += b1;
	b1 = rol64(b1, 13) ^ b6;

	b12 += b15;
	b15 = rol64(b15, 34) ^ b12;

	b14 += b13;
	b13 = rol64(b13, 41) ^ b14;

	b8 += b11;
	b11 = rol64(b11, 59) ^ b8;

	b10 += b9;
	b9 = rol64(b9, 17) ^ b10;

	b0 += b15;
	b15 = rol64(b15, 5) ^ b0;

	b2 += b11;
	b11 = rol64(b11, 20) ^ b2;

	b6 += b13;
	b13 = rol64(b13, 48) ^ b6;

	b4 += b9;
	b9 = rol64(b9, 41) ^ b4;

	b14 += b1;
	b1 = rol64(b1, 47) ^ b14;

	b8 += b5;
	b5 = rol64(b5, 28) ^ b8;

	b10 += b3;
	b3 = rol64(b3, 16) ^ b10;

	b12 += b7;
	b7 = rol64(b7, 25) ^ b12;

	b1 += k12;
	b0 += b1 + k11;
	b1 = rol64(b1, 41) ^ b0;

	b3 += k14;
	b2 += b3 + k13;
	b3 = rol64(b3, 9) ^ b2;

	b5 += k16;
	b4 += b5 + k15;
	b5 = rol64(b5, 37) ^ b4;

	b7 += k1;
	b6 += b7 + k0;
	b7 = rol64(b7, 31) ^ b6;

	b9 += k3;
	b8 += b9 + k2;
	b9 = rol64(b9, 12) ^ b8;

	b11 += k5;
	b10 += b11 + k4;
	b11 = rol64(b11, 47) ^ b10;

	b13 += k7 + t2;
	b12 += b13 + k6;
	b13 = rol64(b13, 44) ^ b12;

	b15 += k9 + 11;
	b14 += b15 + k8 + t0;
	b15 = rol64(b15, 30) ^ b14;

	b0 += b9;
	b9 = rol64(b9, 16) ^ b0;

	b2 += b13;
	b13 = rol64(b13, 34) ^ b2;

	b6 += b11;
	b11 = rol64(b11, 56) ^ b6;

	b4 += b15;
	b15 = rol64(b15, 51) ^ b4;

	b10 += b7;
	b7 = rol64(b7, 4) ^ b10;

	b12 += b3;
	b3 = rol64(b3, 53) ^ b12;

	b14 += b5;
	b5 = rol64(b5, 42) ^ b14;

	b8 += b1;
	b1 = rol64(b1, 41) ^ b8;

	b0 += b7;
	b7 = rol64(b7, 31) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 44) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 47) ^ b4;

	b6 += b1;
	b1 = rol64(b1, 46) ^ b6;

	b12 += b15;
	b15 = rol64(b15, 19) ^ b12;

	b14 += b13;
	b13 = rol64(b13, 42) ^ b14;

	b8 += b11;
	b11 = rol64(b11, 44) ^ b8;

	b10 += b9;
	b9 = rol64(b9, 25) ^ b10;

	b0 += b15;
	b15 = rol64(b15, 9) ^ b0;

	b2 += b11;
	b11 = rol64(b11, 48) ^ b2;

	b6 += b13;
	b13 = rol64(b13, 35) ^ b6;

	b4 += b9;
	b9 = rol64(b9, 52) ^ b4;

	b14 += b1;
	b1 = rol64(b1, 23) ^ b14;

	b8 += b5;
	b5 = rol64(b5, 31) ^ b8;

	b10 += b3;
	b3 = rol64(b3, 37) ^ b10;

	b12 += b7;
	b7 = rol64(b7, 20) ^ b12;

	b1 += k13;
	b0 += b1 + k12;
	b1 = rol64(b1, 24) ^ b0;

	b3 += k15;
	b2 += b3 + k14;
	b3 = rol64(b3, 13) ^ b2;

	b5 += k0;
	b4 += b5 + k16;
	b5 = rol64(b5, 8) ^ b4;

	b7 += k2;
	b6 += b7 + k1;
	b7 = rol64(b7, 47) ^ b6;

	b9 += k4;
	b8 += b9 + k3;
	b9 = rol64(b9, 8) ^ b8;

	b11 += k6;
	b10 += b11 + k5;
	b11 = rol64(b11, 17) ^ b10;

	b13 += k8 + t0;
	b12 += b13 + k7;
	b13 = rol64(b13, 22) ^ b12;

	b15 += k10 + 12;
	b14 += b15 + k9 + t1;
	b15 = rol64(b15, 37) ^ b14;

	b0 += b9;
	b9 = rol64(b9, 38) ^ b0;

	b2 += b13;
	b13 = rol64(b13, 19) ^ b2;

	b6 += b11;
	b11 = rol64(b11, 10) ^ b6;

	b4 += b15;
	b15 = rol64(b15, 55) ^ b4;

	b10 += b7;
	b7 = rol64(b7, 49) ^ b10;

	b12 += b3;
	b3 = rol64(b3, 18) ^ b12;

	b14 += b5;
	b5 = rol64(b5, 23) ^ b14;

	b8 += b1;
	b1 = rol64(b1, 52) ^ b8;

	b0 += b7;
	b7 = rol64(b7, 33) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 4) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 51) ^ b4;

	b6 += b1;
	b1 = rol64(b1, 13) ^ b6;

	b12 += b15;
	b15 = rol64(b15, 34) ^ b12;

	b14 += b13;
	b13 = rol64(b13, 41) ^ b14;

	b8 += b11;
	b11 = rol64(b11, 59) ^ b8;

	b10 += b9;
	b9 = rol64(b9, 17) ^ b10;

	b0 += b15;
	b15 = rol64(b15, 5) ^ b0;

	b2 += b11;
	b11 = rol64(b11, 20) ^ b2;

	b6 += b13;
	b13 = rol64(b13, 48) ^ b6;

	b4 += b9;
	b9 = rol64(b9, 41) ^ b4;

	b14 += b1;
	b1 = rol64(b1, 47) ^ b14;

	b8 += b5;
	b5 = rol64(b5, 28) ^ b8;

	b10 += b3;
	b3 = rol64(b3, 16) ^ b10;

	b12 += b7;
	b7 = rol64(b7, 25) ^ b12;

	b1 += k14;
	b0 += b1 + k13;
	b1 = rol64(b1, 41) ^ b0;

	b3 += k16;
	b2 += b3 + k15;
	b3 = rol64(b3, 9) ^ b2;

	b5 += k1;
	b4 += b5 + k0;
	b5 = rol64(b5, 37) ^ b4;

	b7 += k3;
	b6 += b7 + k2;
	b7 = rol64(b7, 31) ^ b6;

	b9 += k5;
	b8 += b9 + k4;
	b9 = rol64(b9, 12) ^ b8;

	b11 += k7;
	b10 += b11 + k6;
	b11 = rol64(b11, 47) ^ b10;

	b13 += k9 + t1;
	b12 += b13 + k8;
	b13 = rol64(b13, 44) ^ b12;

	b15 += k11 + 13;
	b14 += b15 + k10 + t2;
	b15 = rol64(b15, 30) ^ b14;

	b0 += b9;
	b9 = rol64(b9, 16) ^ b0;

	b2 += b13;
	b13 = rol64(b13, 34) ^ b2;

	b6 += b11;
	b11 = rol64(b11, 56) ^ b6;

	b4 += b15;
	b15 = rol64(b15, 51) ^ b4;

	b10 += b7;
	b7 = rol64(b7, 4) ^ b10;

	b12 += b3;
	b3 = rol64(b3, 53) ^ b12;

	b14 += b5;
	b5 = rol64(b5, 42) ^ b14;

	b8 += b1;
	b1 = rol64(b1, 41) ^ b8;

	b0 += b7;
	b7 = rol64(b7, 31) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 44) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 47) ^ b4;

	b6 += b1;
	b1 = rol64(b1, 46) ^ b6;

	b12 += b15;
	b15 = rol64(b15, 19) ^ b12;

	b14 += b13;
	b13 = rol64(b13, 42) ^ b14;

	b8 += b11;
	b11 = rol64(b11, 44) ^ b8;

	b10 += b9;
	b9 = rol64(b9, 25) ^ b10;

	b0 += b15;
	b15 = rol64(b15, 9) ^ b0;

	b2 += b11;
	b11 = rol64(b11, 48) ^ b2;

	b6 += b13;
	b13 = rol64(b13, 35) ^ b6;

	b4 += b9;
	b9 = rol64(b9, 52) ^ b4;

	b14 += b1;
	b1 = rol64(b1, 23) ^ b14;

	b8 += b5;
	b5 = rol64(b5, 31) ^ b8;

	b10 += b3;
	b3 = rol64(b3, 37) ^ b10;

	b12 += b7;
	b7 = rol64(b7, 20) ^ b12;

	b1 += k15;
	b0 += b1 + k14;
	b1 = rol64(b1, 24) ^ b0;

	b3 += k0;
	b2 += b3 + k16;
	b3 = rol64(b3, 13) ^ b2;

	b5 += k2;
	b4 += b5 + k1;
	b5 = rol64(b5, 8) ^ b4;

	b7 += k4;
	b6 += b7 + k3;
	b7 = rol64(b7, 47) ^ b6;

	b9 += k6;
	b8 += b9 + k5;
	b9 = rol64(b9, 8) ^ b8;

	b11 += k8;
	b10 += b11 + k7;
	b11 = rol64(b11, 17) ^ b10;

	b13 += k10 + t2;
	b12 += b13 + k9;
	b13 = rol64(b13, 22) ^ b12;

	b15 += k12 + 14;
	b14 += b15 + k11 + t0;
	b15 = rol64(b15, 37) ^ b14;

	b0 += b9;
	b9 = rol64(b9, 38) ^ b0;

	b2 += b13;
	b13 = rol64(b13, 19) ^ b2;

	b6 += b11;
	b11 = rol64(b11, 10) ^ b6;

	b4 += b15;
	b15 = rol64(b15, 55) ^ b4;

	b10 += b7;
	b7 = rol64(b7, 49) ^ b10;

	b12 += b3;
	b3 = rol64(b3, 18) ^ b12;

	b14 += b5;
	b5 = rol64(b5, 23) ^ b14;

	b8 += b1;
	b1 = rol64(b1, 52) ^ b8;

	b0 += b7;
	b7 = rol64(b7, 33) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 4) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 51) ^ b4;

	b6 += b1;
	b1 = rol64(b1, 13) ^ b6;

	b12 += b15;
	b15 = rol64(b15, 34) ^ b12;

	b14 += b13;
	b13 = rol64(b13, 41) ^ b14;

	b8 += b11;
	b11 = rol64(b11, 59) ^ b8;

	b10 += b9;
	b9 = rol64(b9, 17) ^ b10;

	b0 += b15;
	b15 = rol64(b15, 5) ^ b0;

	b2 += b11;
	b11 = rol64(b11, 20) ^ b2;

	b6 += b13;
	b13 = rol64(b13, 48) ^ b6;

	b4 += b9;
	b9 = rol64(b9, 41) ^ b4;

	b14 += b1;
	b1 = rol64(b1, 47) ^ b14;

	b8 += b5;
	b5 = rol64(b5, 28) ^ b8;

	b10 += b3;
	b3 = rol64(b3, 16) ^ b10;

	b12 += b7;
	b7 = rol64(b7, 25) ^ b12;

	b1 += k16;
	b0 += b1 + k15;
	b1 = rol64(b1, 41) ^ b0;

	b3 += k1;
	b2 += b3 + k0;
	b3 = rol64(b3, 9) ^ b2;

	b5 += k3;
	b4 += b5 + k2;
	b5 = rol64(b5, 37) ^ b4;

	b7 += k5;
	b6 += b7 + k4;
	b7 = rol64(b7, 31) ^ b6;

	b9 += k7;
	b8 += b9 + k6;
	b9 = rol64(b9, 12) ^ b8;

	b11 += k9;
	b10 += b11 + k8;
	b11 = rol64(b11, 47) ^ b10;

	b13 += k11 + t0;
	b12 += b13 + k10;
	b13 = rol64(b13, 44) ^ b12;

	b15 += k13 + 15;
	b14 += b15 + k12 + t1;
	b15 = rol64(b15, 30) ^ b14;

	b0 += b9;
	b9 = rol64(b9, 16) ^ b0;

	b2 += b13;
	b13 = rol64(b13, 34) ^ b2;

	b6 += b11;
	b11 = rol64(b11, 56) ^ b6;

	b4 += b15;
	b15 = rol64(b15, 51) ^ b4;

	b10 += b7;
	b7 = rol64(b7, 4) ^ b10;

	b12 += b3;
	b3 = rol64(b3, 53) ^ b12;

	b14 += b5;
	b5 = rol64(b5, 42) ^ b14;

	b8 += b1;
	b1 = rol64(b1, 41) ^ b8;

	b0 += b7;
	b7 = rol64(b7, 31) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 44) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 47) ^ b4;

	b6 += b1;
	b1 = rol64(b1, 46) ^ b6;

	b12 += b15;
	b15 = rol64(b15, 19) ^ b12;

	b14 += b13;
	b13 = rol64(b13, 42) ^ b14;

	b8 += b11;
	b11 = rol64(b11, 44) ^ b8;

	b10 += b9;
	b9 = rol64(b9, 25) ^ b10;

	b0 += b15;
	b15 = rol64(b15, 9) ^ b0;

	b2 += b11;
	b11 = rol64(b11, 48) ^ b2;

	b6 += b13;
	b13 = rol64(b13, 35) ^ b6;

	b4 += b9;
	b9 = rol64(b9, 52) ^ b4;

	b14 += b1;
	b1 = rol64(b1, 23) ^ b14;

	b8 += b5;
	b5 = rol64(b5, 31) ^ b8;

	b10 += b3;
	b3 = rol64(b3, 37) ^ b10;

	b12 += b7;
	b7 = rol64(b7, 20) ^ b12;

	b1 += k0;
	b0 += b1 + k16;
	b1 = rol64(b1, 24) ^ b0;

	b3 += k2;
	b2 += b3 + k1;
	b3 = rol64(b3, 13) ^ b2;

	b5 += k4;
	b4 += b5 + k3;
	b5 = rol64(b5, 8) ^ b4;

	b7 += k6;
	b6 += b7 + k5;
	b7 = rol64(b7, 47) ^ b6;

	b9 += k8;
	b8 += b9 + k7;
	b9 = rol64(b9, 8) ^ b8;

	b11 += k10;
	b10 += b11 + k9;
	b11 = rol64(b11, 17) ^ b10;

	b13 += k12 + t1;
	b12 += b13 + k11;
	b13 = rol64(b13, 22) ^ b12;

	b15 += k14 + 16;
	b14 += b15 + k13 + t2;
	b15 = rol64(b15, 37) ^ b14;

	b0 += b9;
	b9 = rol64(b9, 38) ^ b0;

	b2 += b13;
	b13 = rol64(b13, 19) ^ b2;

	b6 += b11;
	b11 = rol64(b11, 10) ^ b6;

	b4 += b15;
	b15 = rol64(b15, 55) ^ b4;

	b10 += b7;
	b7 = rol64(b7, 49) ^ b10;

	b12 += b3;
	b3 = rol64(b3, 18) ^ b12;

	b14 += b5;
	b5 = rol64(b5, 23) ^ b14;

	b8 += b1;
	b1 = rol64(b1, 52) ^ b8;

	b0 += b7;
	b7 = rol64(b7, 33) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 4) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 51) ^ b4;

	b6 += b1;
	b1 = rol64(b1, 13) ^ b6;

	b12 += b15;
	b15 = rol64(b15, 34) ^ b12;

	b14 += b13;
	b13 = rol64(b13, 41) ^ b14;

	b8 += b11;
	b11 = rol64(b11, 59) ^ b8;

	b10 += b9;
	b9 = rol64(b9, 17) ^ b10;

	b0 += b15;
	b15 = rol64(b15, 5) ^ b0;

	b2 += b11;
	b11 = rol64(b11, 20) ^ b2;

	b6 += b13;
	b13 = rol64(b13, 48) ^ b6;

	b4 += b9;
	b9 = rol64(b9, 41) ^ b4;

	b14 += b1;
	b1 = rol64(b1, 47) ^ b14;

	b8 += b5;
	b5 = rol64(b5, 28) ^ b8;

	b10 += b3;
	b3 = rol64(b3, 16) ^ b10;

	b12 += b7;
	b7 = rol64(b7, 25) ^ b12;

	b1 += k1;
	b0 += b1 + k0;
	b1 = rol64(b1, 41) ^ b0;

	b3 += k3;
	b2 += b3 + k2;
	b3 = rol64(b3, 9) ^ b2;

	b5 += k5;
	b4 += b5 + k4;
	b5 = rol64(b5, 37) ^ b4;

	b7 += k7;
	b6 += b7 + k6;
	b7 = rol64(b7, 31) ^ b6;

	b9 += k9;
	b8 += b9 + k8;
	b9 = rol64(b9, 12) ^ b8;

	b11 += k11;
	b10 += b11 + k10;
	b11 = rol64(b11, 47) ^ b10;

	b13 += k13 + t2;
	b12 += b13 + k12;
	b13 = rol64(b13, 44) ^ b12;

	b15 += k15 + 17;
	b14 += b15 + k14 + t0;
	b15 = rol64(b15, 30) ^ b14;

	b0 += b9;
	b9 = rol64(b9, 16) ^ b0;

	b2 += b13;
	b13 = rol64(b13, 34) ^ b2;

	b6 += b11;
	b11 = rol64(b11, 56) ^ b6;

	b4 += b15;
	b15 = rol64(b15, 51) ^ b4;

	b10 += b7;
	b7 = rol64(b7, 4) ^ b10;

	b12 += b3;
	b3 = rol64(b3, 53) ^ b12;

	b14 += b5;
	b5 = rol64(b5, 42) ^ b14;

	b8 += b1;
	b1 = rol64(b1, 41) ^ b8;

	b0 += b7;
	b7 = rol64(b7, 31) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 44) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 47) ^ b4;

	b6 += b1;
	b1 = rol64(b1, 46) ^ b6;

	b12 += b15;
	b15 = rol64(b15, 19) ^ b12;

	b14 += b13;
	b13 = rol64(b13, 42) ^ b14;

	b8 += b11;
	b11 = rol64(b11, 44) ^ b8;

	b10 += b9;
	b9 = rol64(b9, 25) ^ b10;

	b0 += b15;
	b15 = rol64(b15, 9) ^ b0;

	b2 += b11;
	b11 = rol64(b11, 48) ^ b2;

	b6 += b13;
	b13 = rol64(b13, 35) ^ b6;

	b4 += b9;
	b9 = rol64(b9, 52) ^ b4;

	b14 += b1;
	b1 = rol64(b1, 23) ^ b14;

	b8 += b5;
	b5 = rol64(b5, 31) ^ b8;

	b10 += b3;
	b3 = rol64(b3, 37) ^ b10;

	b12 += b7;
	b7 = rol64(b7, 20) ^ b12;

	b1 += k2;
	b0 += b1 + k1;
	b1 = rol64(b1, 24) ^ b0;

	b3 += k4;
	b2 += b3 + k3;
	b3 = rol64(b3, 13) ^ b2;

	b5 += k6;
	b4 += b5 + k5;
	b5 = rol64(b5, 8) ^ b4;

	b7 += k8;
	b6 += b7 + k7;
	b7 = rol64(b7, 47) ^ b6;

	b9 += k10;
	b8 += b9 + k9;
	b9 = rol64(b9, 8) ^ b8;

	b11 += k12;
	b10 += b11 + k11;
	b11 = rol64(b11, 17) ^ b10;

	b13 += k14 + t0;
	b12 += b13 + k13;
	b13 = rol64(b13, 22) ^ b12;

	b15 += k16 + 18;
	b14 += b15 + k15 + t1;
	b15 = rol64(b15, 37) ^ b14;

	b0 += b9;
	b9 = rol64(b9, 38) ^ b0;

	b2 += b13;
	b13 = rol64(b13, 19) ^ b2;

	b6 += b11;
	b11 = rol64(b11, 10) ^ b6;

	b4 += b15;
	b15 = rol64(b15, 55) ^ b4;

	b10 += b7;
	b7 = rol64(b7, 49) ^ b10;

	b12 += b3;
	b3 = rol64(b3, 18) ^ b12;

	b14 += b5;
	b5 = rol64(b5, 23) ^ b14;

	b8 += b1;
	b1 = rol64(b1, 52) ^ b8;

	b0 += b7;
	b7 = rol64(b7, 33) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 4) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 51) ^ b4;

	b6 += b1;
	b1 = rol64(b1, 13) ^ b6;

	b12 += b15;
	b15 = rol64(b15, 34) ^ b12;

	b14 += b13;
	b13 = rol64(b13, 41) ^ b14;

	b8 += b11;
	b11 = rol64(b11, 59) ^ b8;

	b10 += b9;
	b9 = rol64(b9, 17) ^ b10;

	b0 += b15;
	b15 = rol64(b15, 5) ^ b0;

	b2 += b11;
	b11 = rol64(b11, 20) ^ b2;

	b6 += b13;
	b13 = rol64(b13, 48) ^ b6;

	b4 += b9;
	b9 = rol64(b9, 41) ^ b4;

	b14 += b1;
	b1 = rol64(b1, 47) ^ b14;

	b8 += b5;
	b5 = rol64(b5, 28) ^ b8;

	b10 += b3;
	b3 = rol64(b3, 16) ^ b10;

	b12 += b7;
	b7 = rol64(b7, 25) ^ b12;

	b1 += k3;
	b0 += b1 + k2;
	b1 = rol64(b1, 41) ^ b0;

	b3 += k5;
	b2 += b3 + k4;
	b3 = rol64(b3, 9) ^ b2;

	b5 += k7;
	b4 += b5 + k6;
	b5 = rol64(b5, 37) ^ b4;

	b7 += k9;
	b6 += b7 + k8;
	b7 = rol64(b7, 31) ^ b6;

	b9 += k11;
	b8 += b9 + k10;
	b9 = rol64(b9, 12) ^ b8;

	b11 += k13;
	b10 += b11 + k12;
	b11 = rol64(b11, 47) ^ b10;

	b13 += k15 + t1;
	b12 += b13 + k14;
	b13 = rol64(b13, 44) ^ b12;

	b15 += k0 + 19;
	b14 += b15 + k16 + t2;
	b15 = rol64(b15, 30) ^ b14;

	b0 += b9;
	b9 = rol64(b9, 16) ^ b0;

	b2 += b13;
	b13 = rol64(b13, 34) ^ b2;

	b6 += b11;
	b11 = rol64(b11, 56) ^ b6;

	b4 += b15;
	b15 = rol64(b15, 51) ^ b4;

	b10 += b7;
	b7 = rol64(b7, 4) ^ b10;

	b12 += b3;
	b3 = rol64(b3, 53) ^ b12;

	b14 += b5;
	b5 = rol64(b5, 42) ^ b14;

	b8 += b1;
	b1 = rol64(b1, 41) ^ b8;

	b0 += b7;
	b7 = rol64(b7, 31) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 44) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 47) ^ b4;

	b6 += b1;
	b1 = rol64(b1, 46) ^ b6;

	b12 += b15;
	b15 = rol64(b15, 19) ^ b12;

	b14 += b13;
	b13 = rol64(b13, 42) ^ b14;

	b8 += b11;
	b11 = rol64(b11, 44) ^ b8;

	b10 += b9;
	b9 = rol64(b9, 25) ^ b10;

	b0 += b15;
	b15 = rol64(b15, 9) ^ b0;

	b2 += b11;
	b11 = rol64(b11, 48) ^ b2;

	b6 += b13;
	b13 = rol64(b13, 35) ^ b6;

	b4 += b9;
	b9 = rol64(b9, 52) ^ b4;

	b14 += b1;
	b1 = rol64(b1, 23) ^ b14;

	b8 += b5;
	b5 = rol64(b5, 31) ^ b8;

	b10 += b3;
	b3 = rol64(b3, 37) ^ b10;

	b12 += b7;
	b7 = rol64(b7, 20) ^ b12;

	output[0] = cpu_to_le64(b0 + k3);
	output[1] = cpu_to_le64(b1 + k4);
	output[2] = cpu_to_le64(b2 + k5);
	output[3] = cpu_to_le64(b3 + k6);
	output[4] = cpu_to_le64(b4 + k7);
	output[5] = cpu_to_le64(b5 + k8);
	output[6] = cpu_to_le64(b6 + k9);
	output[7] = cpu_to_le64(b7 + k10);
	output[8] = cpu_to_le64(b8 + k11);
	output[9] = cpu_to_le64(b9 + k12);
	output[10] = cpu_to_le64(b10 + k13);
	output[11] = cpu_to_le64(b11 + k14);
	output[12] = cpu_to_le64(b12 + k15);
	output[13] = cpu_to_le64(b13 + k16 + t2);
	output[14] = cpu_to_le64(b14 + k0 + t0);
	output[15] = cpu_to_le64(b15 + k1 + 20);
}

void threefish_decrypt_1024(const struct threefish_key *key_ctx, const u64 *input,
			   u64 *output, u64 t0)
// Taken from: 
// https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/drivers/staging/skein/threefish_block.c?h=linux-4.17.y#n5430
{
	u64 b0 = input[0], b1 = input[1],
	    b2 = input[2], b3 = input[3],
	    b4 = input[4], b5 = input[5],
	    b6 = input[6], b7 = input[7],
	    b8 = input[8], b9 = input[9],
	    b10 = input[10], b11 = input[11],
	    b12 = input[12], b13 = input[13],
	    b14 = input[14], b15 = input[15];
	u64 k0 = key_ctx->key[0], k1 = key_ctx->key[1],
	    k2 = key_ctx->key[2], k3 = key_ctx->key[3],
	    k4 = key_ctx->key[4], k5 = key_ctx->key[5],
	    k6 = key_ctx->key[6], k7 = key_ctx->key[7],
	    k8 = key_ctx->key[8], k9 = key_ctx->key[9],
	    k10 = key_ctx->key[10], k11 = key_ctx->key[11],
	    k12 = key_ctx->key[12], k13 = key_ctx->key[13],
	    k14 = key_ctx->key[14], k15 = key_ctx->key[15],
	    k16 = key_ctx->key[16];
	//u64 t0 = key_ctx->tweak[0], t1 = key_ctx->tweak[1],
	//    t2 = key_ctx->tweak[2];
	u64 tmp;

	b0 -= k3;
	b1 -= k4;
	b2 -= k5;
	b3 -= k6;
	b4 -= k7;
	b5 -= k8;
	b6 -= k9;
	b7 -= k10;
	b8 -= k11;
	b9 -= k12;
	b10 -= k13;
	b11 -= k14;
	b12 -= k15;
	b13 -= k16 + t2;
	b14 -= k0 + t0;
	b15 -= k1 + 20;
	tmp = b7 ^ b12;
	b7 = ror64(tmp, 20);
	b12 -= b7;

	tmp = b3 ^ b10;
	b3 = ror64(tmp, 37);
	b10 -= b3;

	tmp = b5 ^ b8;
	b5 = ror64(tmp, 31);
	b8 -= b5;

	tmp = b1 ^ b14;
	b1 = ror64(tmp, 23);
	b14 -= b1;

	tmp = b9 ^ b4;
	b9 = ror64(tmp, 52);
	b4 -= b9;

	tmp = b13 ^ b6;
	b13 = ror64(tmp, 35);
	b6 -= b13;

	tmp = b11 ^ b2;
	b11 = ror64(tmp, 48);
	b2 -= b11;

	tmp = b15 ^ b0;
	b15 = ror64(tmp, 9);
	b0 -= b15;

	tmp = b9 ^ b10;
	b9 = ror64(tmp, 25);
	b10 -= b9;

	tmp = b11 ^ b8;
	b11 = ror64(tmp, 44);
	b8 -= b11;

	tmp = b13 ^ b14;
	b13 = ror64(tmp, 42);
	b14 -= b13;

	tmp = b15 ^ b12;
	b15 = ror64(tmp, 19);
	b12 -= b15;

	tmp = b1 ^ b6;
	b1 = ror64(tmp, 46);
	b6 -= b1;

	tmp = b3 ^ b4;
	b3 = ror64(tmp, 47);
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = ror64(tmp, 44);
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = ror64(tmp, 31);
	b0 -= b7;

	tmp = b1 ^ b8;
	b1 = ror64(tmp, 41);
	b8 -= b1;

	tmp = b5 ^ b14;
	b5 = ror64(tmp, 42);
	b14 -= b5;

	tmp = b3 ^ b12;
	b3 = ror64(tmp, 53);
	b12 -= b3;

	tmp = b7 ^ b10;
	b7 = ror64(tmp, 4);
	b10 -= b7;

	tmp = b15 ^ b4;
	b15 = ror64(tmp, 51);
	b4 -= b15;

	tmp = b11 ^ b6;
	b11 = ror64(tmp, 56);
	b6 -= b11;

	tmp = b13 ^ b2;
	b13 = ror64(tmp, 34);
	b2 -= b13;

	tmp = b9 ^ b0;
	b9 = ror64(tmp, 16);
	b0 -= b9;

	tmp = b15 ^ b14;
	b15 = ror64(tmp, 30);
	b14 -= b15 + k16 + t2;
	b15 -= k0 + 19;

	tmp = b13 ^ b12;
	b13 = ror64(tmp, 44);
	b12 -= b13 + k14;
	b13 -= k15 + t1;

	tmp = b11 ^ b10;
	b11 = ror64(tmp, 47);
	b10 -= b11 + k12;
	b11 -= k13;

	tmp = b9 ^ b8;
	b9 = ror64(tmp, 12);
	b8 -= b9 + k10;
	b9 -= k11;

	tmp = b7 ^ b6;
	b7 = ror64(tmp, 31);
	b6 -= b7 + k8;
	b7 -= k9;

	tmp = b5 ^ b4;
	b5 = ror64(tmp, 37);
	b4 -= b5 + k6;
	b5 -= k7;

	tmp = b3 ^ b2;
	b3 = ror64(tmp, 9);
	b2 -= b3 + k4;
	b3 -= k5;

	tmp = b1 ^ b0;
	b1 = ror64(tmp, 41);
	b0 -= b1 + k2;
	b1 -= k3;

	tmp = b7 ^ b12;
	b7 = ror64(tmp, 25);
	b12 -= b7;

	tmp = b3 ^ b10;
	b3 = ror64(tmp, 16);
	b10 -= b3;

	tmp = b5 ^ b8;
	b5 = ror64(tmp, 28);
	b8 -= b5;

	tmp = b1 ^ b14;
	b1 = ror64(tmp, 47);
	b14 -= b1;

	tmp = b9 ^ b4;
	b9 = ror64(tmp, 41);
	b4 -= b9;

	tmp = b13 ^ b6;
	b13 = ror64(tmp, 48);
	b6 -= b13;

	tmp = b11 ^ b2;
	b11 = ror64(tmp, 20);
	b2 -= b11;

	tmp = b15 ^ b0;
	b15 = ror64(tmp, 5);
	b0 -= b15;

	tmp = b9 ^ b10;
	b9 = ror64(tmp, 17);
	b10 -= b9;

	tmp = b11 ^ b8;
	b11 = ror64(tmp, 59);
	b8 -= b11;

	tmp = b13 ^ b14;
	b13 = ror64(tmp, 41);
	b14 -= b13;

	tmp = b15 ^ b12;
	b15 = ror64(tmp, 34);
	b12 -= b15;

	tmp = b1 ^ b6;
	b1 = ror64(tmp, 13);
	b6 -= b1;

	tmp = b3 ^ b4;
	b3 = ror64(tmp, 51);
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = ror64(tmp, 4);
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = ror64(tmp, 33);
	b0 -= b7;

	tmp = b1 ^ b8;
	b1 = ror64(tmp, 52);
	b8 -= b1;

	tmp = b5 ^ b14;
	b5 = ror64(tmp, 23);
	b14 -= b5;

	tmp = b3 ^ b12;
	b3 = ror64(tmp, 18);
	b12 -= b3;

	tmp = b7 ^ b10;
	b7 = ror64(tmp, 49);
	b10 -= b7;

	tmp = b15 ^ b4;
	b15 = ror64(tmp, 55);
	b4 -= b15;

	tmp = b11 ^ b6;
	b11 = ror64(tmp, 10);
	b6 -= b11;

	tmp = b13 ^ b2;
	b13 = ror64(tmp, 19);
	b2 -= b13;

	tmp = b9 ^ b0;
	b9 = ror64(tmp, 38);
	b0 -= b9;

	tmp = b15 ^ b14;
	b15 = ror64(tmp, 37);
	b14 -= b15 + k15 + t1;
	b15 -= k16 + 18;

	tmp = b13 ^ b12;
	b13 = ror64(tmp, 22);
	b12 -= b13 + k13;
	b13 -= k14 + t0;

	tmp = b11 ^ b10;
	b11 = ror64(tmp, 17);
	b10 -= b11 + k11;
	b11 -= k12;

	tmp = b9 ^ b8;
	b9 = ror64(tmp, 8);
	b8 -= b9 + k9;
	b9 -= k10;

	tmp = b7 ^ b6;
	b7 = ror64(tmp, 47);
	b6 -= b7 + k7;
	b7 -= k8;

	tmp = b5 ^ b4;
	b5 = ror64(tmp, 8);
	b4 -= b5 + k5;
	b5 -= k6;

	tmp = b3 ^ b2;
	b3 = ror64(tmp, 13);
	b2 -= b3 + k3;
	b3 -= k4;

	tmp = b1 ^ b0;
	b1 = ror64(tmp, 24);
	b0 -= b1 + k1;
	b1 -= k2;

	tmp = b7 ^ b12;
	b7 = ror64(tmp, 20);
	b12 -= b7;

	tmp = b3 ^ b10;
	b3 = ror64(tmp, 37);
	b10 -= b3;

	tmp = b5 ^ b8;
	b5 = ror64(tmp, 31);
	b8 -= b5;

	tmp = b1 ^ b14;
	b1 = ror64(tmp, 23);
	b14 -= b1;

	tmp = b9 ^ b4;
	b9 = ror64(tmp, 52);
	b4 -= b9;

	tmp = b13 ^ b6;
	b13 = ror64(tmp, 35);
	b6 -= b13;

	tmp = b11 ^ b2;
	b11 = ror64(tmp, 48);
	b2 -= b11;

	tmp = b15 ^ b0;
	b15 = ror64(tmp, 9);
	b0 -= b15;

	tmp = b9 ^ b10;
	b9 = ror64(tmp, 25);
	b10 -= b9;

	tmp = b11 ^ b8;
	b11 = ror64(tmp, 44);
	b8 -= b11;

	tmp = b13 ^ b14;
	b13 = ror64(tmp, 42);
	b14 -= b13;

	tmp = b15 ^ b12;
	b15 = ror64(tmp, 19);
	b12 -= b15;

	tmp = b1 ^ b6;
	b1 = ror64(tmp, 46);
	b6 -= b1;

	tmp = b3 ^ b4;
	b3 = ror64(tmp, 47);
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = ror64(tmp, 44);
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = ror64(tmp, 31);
	b0 -= b7;

	tmp = b1 ^ b8;
	b1 = ror64(tmp, 41);
	b8 -= b1;

	tmp = b5 ^ b14;
	b5 = ror64(tmp, 42);
	b14 -= b5;

	tmp = b3 ^ b12;
	b3 = ror64(tmp, 53);
	b12 -= b3;

	tmp = b7 ^ b10;
	b7 = ror64(tmp, 4);
	b10 -= b7;

	tmp = b15 ^ b4;
	b15 = ror64(tmp, 51);
	b4 -= b15;

	tmp = b11 ^ b6;
	b11 = ror64(tmp, 56);
	b6 -= b11;

	tmp = b13 ^ b2;
	b13 = ror64(tmp, 34);
	b2 -= b13;

	tmp = b9 ^ b0;
	b9 = ror64(tmp, 16);
	b0 -= b9;

	tmp = b15 ^ b14;
	b15 = ror64(tmp, 30);
	b14 -= b15 + k14 + t0;
	b15 -= k15 + 17;

	tmp = b13 ^ b12;
	b13 = ror64(tmp, 44);
	b12 -= b13 + k12;
	b13 -= k13 + t2;

	tmp = b11 ^ b10;
	b11 = ror64(tmp, 47);
	b10 -= b11 + k10;
	b11 -= k11;

	tmp = b9 ^ b8;
	b9 = ror64(tmp, 12);
	b8 -= b9 + k8;
	b9 -= k9;

	tmp = b7 ^ b6;
	b7 = ror64(tmp, 31);
	b6 -= b7 + k6;
	b7 -= k7;

	tmp = b5 ^ b4;
	b5 = ror64(tmp, 37);
	b4 -= b5 + k4;
	b5 -= k5;

	tmp = b3 ^ b2;
	b3 = ror64(tmp, 9);
	b2 -= b3 + k2;
	b3 -= k3;

	tmp = b1 ^ b0;
	b1 = ror64(tmp, 41);
	b0 -= b1 + k0;
	b1 -= k1;

	tmp = b7 ^ b12;
	b7 = ror64(tmp, 25);
	b12 -= b7;

	tmp = b3 ^ b10;
	b3 = ror64(tmp, 16);
	b10 -= b3;

	tmp = b5 ^ b8;
	b5 = ror64(tmp, 28);
	b8 -= b5;

	tmp = b1 ^ b14;
	b1 = ror64(tmp, 47);
	b14 -= b1;

	tmp = b9 ^ b4;
	b9 = ror64(tmp, 41);
	b4 -= b9;

	tmp = b13 ^ b6;
	b13 = ror64(tmp, 48);
	b6 -= b13;

	tmp = b11 ^ b2;
	b11 = ror64(tmp, 20);
	b2 -= b11;

	tmp = b15 ^ b0;
	b15 = ror64(tmp, 5);
	b0 -= b15;

	tmp = b9 ^ b10;
	b9 = ror64(tmp, 17);
	b10 -= b9;

	tmp = b11 ^ b8;
	b11 = ror64(tmp, 59);
	b8 -= b11;

	tmp = b13 ^ b14;
	b13 = ror64(tmp, 41);
	b14 -= b13;

	tmp = b15 ^ b12;
	b15 = ror64(tmp, 34);
	b12 -= b15;

	tmp = b1 ^ b6;
	b1 = ror64(tmp, 13);
	b6 -= b1;

	tmp = b3 ^ b4;
	b3 = ror64(tmp, 51);
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = ror64(tmp, 4);
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = ror64(tmp, 33);
	b0 -= b7;

	tmp = b1 ^ b8;
	b1 = ror64(tmp, 52);
	b8 -= b1;

	tmp = b5 ^ b14;
	b5 = ror64(tmp, 23);
	b14 -= b5;

	tmp = b3 ^ b12;
	b3 = ror64(tmp, 18);
	b12 -= b3;

	tmp = b7 ^ b10;
	b7 = ror64(tmp, 49);
	b10 -= b7;

	tmp = b15 ^ b4;
	b15 = ror64(tmp, 55);
	b4 -= b15;

	tmp = b11 ^ b6;
	b11 = ror64(tmp, 10);
	b6 -= b11;

	tmp = b13 ^ b2;
	b13 = ror64(tmp, 19);
	b2 -= b13;

	tmp = b9 ^ b0;
	b9 = ror64(tmp, 38);
	b0 -= b9;

	tmp = b15 ^ b14;
	b15 = ror64(tmp, 37);
	b14 -= b15 + k13 + t2;
	b15 -= k14 + 16;

	tmp = b13 ^ b12;
	b13 = ror64(tmp, 22);
	b12 -= b13 + k11;
	b13 -= k12 + t1;

	tmp = b11 ^ b10;
	b11 = ror64(tmp, 17);
	b10 -= b11 + k9;
	b11 -= k10;

	tmp = b9 ^ b8;
	b9 = ror64(tmp, 8);
	b8 -= b9 + k7;
	b9 -= k8;

	tmp = b7 ^ b6;
	b7 = ror64(tmp, 47);
	b6 -= b7 + k5;
	b7 -= k6;

	tmp = b5 ^ b4;
	b5 = ror64(tmp, 8);
	b4 -= b5 + k3;
	b5 -= k4;

	tmp = b3 ^ b2;
	b3 = ror64(tmp, 13);
	b2 -= b3 + k1;
	b3 -= k2;

	tmp = b1 ^ b0;
	b1 = ror64(tmp, 24);
	b0 -= b1 + k16;
	b1 -= k0;

	tmp = b7 ^ b12;
	b7 = ror64(tmp, 20);
	b12 -= b7;

	tmp = b3 ^ b10;
	b3 = ror64(tmp, 37);
	b10 -= b3;

	tmp = b5 ^ b8;
	b5 = ror64(tmp, 31);
	b8 -= b5;

	tmp = b1 ^ b14;
	b1 = ror64(tmp, 23);
	b14 -= b1;

	tmp = b9 ^ b4;
	b9 = ror64(tmp, 52);
	b4 -= b9;

	tmp = b13 ^ b6;
	b13 = ror64(tmp, 35);
	b6 -= b13;

	tmp = b11 ^ b2;
	b11 = ror64(tmp, 48);
	b2 -= b11;

	tmp = b15 ^ b0;
	b15 = ror64(tmp, 9);
	b0 -= b15;

	tmp = b9 ^ b10;
	b9 = ror64(tmp, 25);
	b10 -= b9;

	tmp = b11 ^ b8;
	b11 = ror64(tmp, 44);
	b8 -= b11;

	tmp = b13 ^ b14;
	b13 = ror64(tmp, 42);
	b14 -= b13;

	tmp = b15 ^ b12;
	b15 = ror64(tmp, 19);
	b12 -= b15;

	tmp = b1 ^ b6;
	b1 = ror64(tmp, 46);
	b6 -= b1;

	tmp = b3 ^ b4;
	b3 = ror64(tmp, 47);
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = ror64(tmp, 44);
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = ror64(tmp, 31);
	b0 -= b7;

	tmp = b1 ^ b8;
	b1 = ror64(tmp, 41);
	b8 -= b1;

	tmp = b5 ^ b14;
	b5 = ror64(tmp, 42);
	b14 -= b5;

	tmp = b3 ^ b12;
	b3 = ror64(tmp, 53);
	b12 -= b3;

	tmp = b7 ^ b10;
	b7 = ror64(tmp, 4);
	b10 -= b7;

	tmp = b15 ^ b4;
	b15 = ror64(tmp, 51);
	b4 -= b15;

	tmp = b11 ^ b6;
	b11 = ror64(tmp, 56);
	b6 -= b11;

	tmp = b13 ^ b2;
	b13 = ror64(tmp, 34);
	b2 -= b13;

	tmp = b9 ^ b0;
	b9 = ror64(tmp, 16);
	b0 -= b9;

	tmp = b15 ^ b14;
	b15 = ror64(tmp, 30);
	b14 -= b15 + k12 + t1;
	b15 -= k13 + 15;

	tmp = b13 ^ b12;
	b13 = ror64(tmp, 44);
	b12 -= b13 + k10;
	b13 -= k11 + t0;

	tmp = b11 ^ b10;
	b11 = ror64(tmp, 47);
	b10 -= b11 + k8;
	b11 -= k9;

	tmp = b9 ^ b8;
	b9 = ror64(tmp, 12);
	b8 -= b9 + k6;
	b9 -= k7;

	tmp = b7 ^ b6;
	b7 = ror64(tmp, 31);
	b6 -= b7 + k4;
	b7 -= k5;

	tmp = b5 ^ b4;
	b5 = ror64(tmp, 37);
	b4 -= b5 + k2;
	b5 -= k3;

	tmp = b3 ^ b2;
	b3 = ror64(tmp, 9);
	b2 -= b3 + k0;
	b3 -= k1;

	tmp = b1 ^ b0;
	b1 = ror64(tmp, 41);
	b0 -= b1 + k15;
	b1 -= k16;

	tmp = b7 ^ b12;
	b7 = ror64(tmp, 25);
	b12 -= b7;

	tmp = b3 ^ b10;
	b3 = ror64(tmp, 16);
	b10 -= b3;

	tmp = b5 ^ b8;
	b5 = ror64(tmp, 28);
	b8 -= b5;

	tmp = b1 ^ b14;
	b1 = ror64(tmp, 47);
	b14 -= b1;

	tmp = b9 ^ b4;
	b9 = ror64(tmp, 41);
	b4 -= b9;

	tmp = b13 ^ b6;
	b13 = ror64(tmp, 48);
	b6 -= b13;

	tmp = b11 ^ b2;
	b11 = ror64(tmp, 20);
	b2 -= b11;

	tmp = b15 ^ b0;
	b15 = ror64(tmp, 5);
	b0 -= b15;

	tmp = b9 ^ b10;
	b9 = ror64(tmp, 17);
	b10 -= b9;

	tmp = b11 ^ b8;
	b11 = ror64(tmp, 59);
	b8 -= b11;

	tmp = b13 ^ b14;
	b13 = ror64(tmp, 41);
	b14 -= b13;

	tmp = b15 ^ b12;
	b15 = ror64(tmp, 34);
	b12 -= b15;

	tmp = b1 ^ b6;
	b1 = ror64(tmp, 13);
	b6 -= b1;

	tmp = b3 ^ b4;
	b3 = ror64(tmp, 51);
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = ror64(tmp, 4);
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = ror64(tmp, 33);
	b0 -= b7;

	tmp = b1 ^ b8;
	b1 = ror64(tmp, 52);
	b8 -= b1;

	tmp = b5 ^ b14;
	b5 = ror64(tmp, 23);
	b14 -= b5;

	tmp = b3 ^ b12;
	b3 = ror64(tmp, 18);
	b12 -= b3;

	tmp = b7 ^ b10;
	b7 = ror64(tmp, 49);
	b10 -= b7;

	tmp = b15 ^ b4;
	b15 = ror64(tmp, 55);
	b4 -= b15;

	tmp = b11 ^ b6;
	b11 = ror64(tmp, 10);
	b6 -= b11;

	tmp = b13 ^ b2;
	b13 = ror64(tmp, 19);
	b2 -= b13;

	tmp = b9 ^ b0;
	b9 = ror64(tmp, 38);
	b0 -= b9;

	tmp = b15 ^ b14;
	b15 = ror64(tmp, 37);
	b14 -= b15 + k11 + t0;
	b15 -= k12 + 14;

	tmp = b13 ^ b12;
	b13 = ror64(tmp, 22);
	b12 -= b13 + k9;
	b13 -= k10 + t2;

	tmp = b11 ^ b10;
	b11 = ror64(tmp, 17);
	b10 -= b11 + k7;
	b11 -= k8;

	tmp = b9 ^ b8;
	b9 = ror64(tmp, 8);
	b8 -= b9 + k5;
	b9 -= k6;

	tmp = b7 ^ b6;
	b7 = ror64(tmp, 47);
	b6 -= b7 + k3;
	b7 -= k4;

	tmp = b5 ^ b4;
	b5 = ror64(tmp, 8);
	b4 -= b5 + k1;
	b5 -= k2;

	tmp = b3 ^ b2;
	b3 = ror64(tmp, 13);
	b2 -= b3 + k16;
	b3 -= k0;

	tmp = b1 ^ b0;
	b1 = ror64(tmp, 24);
	b0 -= b1 + k14;
	b1 -= k15;

	tmp = b7 ^ b12;
	b7 = ror64(tmp, 20);
	b12 -= b7;

	tmp = b3 ^ b10;
	b3 = ror64(tmp, 37);
	b10 -= b3;

	tmp = b5 ^ b8;
	b5 = ror64(tmp, 31);
	b8 -= b5;

	tmp = b1 ^ b14;
	b1 = ror64(tmp, 23);
	b14 -= b1;

	tmp = b9 ^ b4;
	b9 = ror64(tmp, 52);
	b4 -= b9;

	tmp = b13 ^ b6;
	b13 = ror64(tmp, 35);
	b6 -= b13;

	tmp = b11 ^ b2;
	b11 = ror64(tmp, 48);
	b2 -= b11;

	tmp = b15 ^ b0;
	b15 = ror64(tmp, 9);
	b0 -= b15;

	tmp = b9 ^ b10;
	b9 = ror64(tmp, 25);
	b10 -= b9;

	tmp = b11 ^ b8;
	b11 = ror64(tmp, 44);
	b8 -= b11;

	tmp = b13 ^ b14;
	b13 = ror64(tmp, 42);
	b14 -= b13;

	tmp = b15 ^ b12;
	b15 = ror64(tmp, 19);
	b12 -= b15;

	tmp = b1 ^ b6;
	b1 = ror64(tmp, 46);
	b6 -= b1;

	tmp = b3 ^ b4;
	b3 = ror64(tmp, 47);
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = ror64(tmp, 44);
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = ror64(tmp, 31);
	b0 -= b7;

	tmp = b1 ^ b8;
	b1 = ror64(tmp, 41);
	b8 -= b1;

	tmp = b5 ^ b14;
	b5 = ror64(tmp, 42);
	b14 -= b5;

	tmp = b3 ^ b12;
	b3 = ror64(tmp, 53);
	b12 -= b3;

	tmp = b7 ^ b10;
	b7 = ror64(tmp, 4);
	b10 -= b7;

	tmp = b15 ^ b4;
	b15 = ror64(tmp, 51);
	b4 -= b15;

	tmp = b11 ^ b6;
	b11 = ror64(tmp, 56);
	b6 -= b11;

	tmp = b13 ^ b2;
	b13 = ror64(tmp, 34);
	b2 -= b13;

	tmp = b9 ^ b0;
	b9 = ror64(tmp, 16);
	b0 -= b9;

	tmp = b15 ^ b14;
	b15 = ror64(tmp, 30);
	b14 -= b15 + k10 + t2;
	b15 -= k11 + 13;

	tmp = b13 ^ b12;
	b13 = ror64(tmp, 44);
	b12 -= b13 + k8;
	b13 -= k9 + t1;

	tmp = b11 ^ b10;
	b11 = ror64(tmp, 47);
	b10 -= b11 + k6;
	b11 -= k7;

	tmp = b9 ^ b8;
	b9 = ror64(tmp, 12);
	b8 -= b9 + k4;
	b9 -= k5;

	tmp = b7 ^ b6;
	b7 = ror64(tmp, 31);
	b6 -= b7 + k2;
	b7 -= k3;

	tmp = b5 ^ b4;
	b5 = ror64(tmp, 37);
	b4 -= b5 + k0;
	b5 -= k1;

	tmp = b3 ^ b2;
	b3 = ror64(tmp, 9);
	b2 -= b3 + k15;
	b3 -= k16;

	tmp = b1 ^ b0;
	b1 = ror64(tmp, 41);
	b0 -= b1 + k13;
	b1 -= k14;

	tmp = b7 ^ b12;
	b7 = ror64(tmp, 25);
	b12 -= b7;

	tmp = b3 ^ b10;
	b3 = ror64(tmp, 16);
	b10 -= b3;

	tmp = b5 ^ b8;
	b5 = ror64(tmp, 28);
	b8 -= b5;

	tmp = b1 ^ b14;
	b1 = ror64(tmp, 47);
	b14 -= b1;

	tmp = b9 ^ b4;
	b9 = ror64(tmp, 41);
	b4 -= b9;

	tmp = b13 ^ b6;
	b13 = ror64(tmp, 48);
	b6 -= b13;

	tmp = b11 ^ b2;
	b11 = ror64(tmp, 20);
	b2 -= b11;

	tmp = b15 ^ b0;
	b15 = ror64(tmp, 5);
	b0 -= b15;

	tmp = b9 ^ b10;
	b9 = ror64(tmp, 17);
	b10 -= b9;

	tmp = b11 ^ b8;
	b11 = ror64(tmp, 59);
	b8 -= b11;

	tmp = b13 ^ b14;
	b13 = ror64(tmp, 41);
	b14 -= b13;

	tmp = b15 ^ b12;
	b15 = ror64(tmp, 34);
	b12 -= b15;

	tmp = b1 ^ b6;
	b1 = ror64(tmp, 13);
	b6 -= b1;

	tmp = b3 ^ b4;
	b3 = ror64(tmp, 51);
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = ror64(tmp, 4);
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = ror64(tmp, 33);
	b0 -= b7;

	tmp = b1 ^ b8;
	b1 = ror64(tmp, 52);
	b8 -= b1;

	tmp = b5 ^ b14;
	b5 = ror64(tmp, 23);
	b14 -= b5;

	tmp = b3 ^ b12;
	b3 = ror64(tmp, 18);
	b12 -= b3;

	tmp = b7 ^ b10;
	b7 = ror64(tmp, 49);
	b10 -= b7;

	tmp = b15 ^ b4;
	b15 = ror64(tmp, 55);
	b4 -= b15;

	tmp = b11 ^ b6;
	b11 = ror64(tmp, 10);
	b6 -= b11;

	tmp = b13 ^ b2;
	b13 = ror64(tmp, 19);
	b2 -= b13;

	tmp = b9 ^ b0;
	b9 = ror64(tmp, 38);
	b0 -= b9;

	tmp = b15 ^ b14;
	b15 = ror64(tmp, 37);
	b14 -= b15 + k9 + t1;
	b15 -= k10 + 12;

	tmp = b13 ^ b12;
	b13 = ror64(tmp, 22);
	b12 -= b13 + k7;
	b13 -= k8 + t0;

	tmp = b11 ^ b10;
	b11 = ror64(tmp, 17);
	b10 -= b11 + k5;
	b11 -= k6;

	tmp = b9 ^ b8;
	b9 = ror64(tmp, 8);
	b8 -= b9 + k3;
	b9 -= k4;

	tmp = b7 ^ b6;
	b7 = ror64(tmp, 47);
	b6 -= b7 + k1;
	b7 -= k2;

	tmp = b5 ^ b4;
	b5 = ror64(tmp, 8);
	b4 -= b5 + k16;
	b5 -= k0;

	tmp = b3 ^ b2;
	b3 = ror64(tmp, 13);
	b2 -= b3 + k14;
	b3 -= k15;

	tmp = b1 ^ b0;
	b1 = ror64(tmp, 24);
	b0 -= b1 + k12;
	b1 -= k13;

	tmp = b7 ^ b12;
	b7 = ror64(tmp, 20);
	b12 -= b7;

	tmp = b3 ^ b10;
	b3 = ror64(tmp, 37);
	b10 -= b3;

	tmp = b5 ^ b8;
	b5 = ror64(tmp, 31);
	b8 -= b5;

	tmp = b1 ^ b14;
	b1 = ror64(tmp, 23);
	b14 -= b1;

	tmp = b9 ^ b4;
	b9 = ror64(tmp, 52);
	b4 -= b9;

	tmp = b13 ^ b6;
	b13 = ror64(tmp, 35);
	b6 -= b13;

	tmp = b11 ^ b2;
	b11 = ror64(tmp, 48);
	b2 -= b11;

	tmp = b15 ^ b0;
	b15 = ror64(tmp, 9);
	b0 -= b15;

	tmp = b9 ^ b10;
	b9 = ror64(tmp, 25);
	b10 -= b9;

	tmp = b11 ^ b8;
	b11 = ror64(tmp, 44);
	b8 -= b11;

	tmp = b13 ^ b14;
	b13 = ror64(tmp, 42);
	b14 -= b13;

	tmp = b15 ^ b12;
	b15 = ror64(tmp, 19);
	b12 -= b15;

	tmp = b1 ^ b6;
	b1 = ror64(tmp, 46);
	b6 -= b1;

	tmp = b3 ^ b4;
	b3 = ror64(tmp, 47);
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = ror64(tmp, 44);
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = ror64(tmp, 31);
	b0 -= b7;

	tmp = b1 ^ b8;
	b1 = ror64(tmp, 41);
	b8 -= b1;

	tmp = b5 ^ b14;
	b5 = ror64(tmp, 42);
	b14 -= b5;

	tmp = b3 ^ b12;
	b3 = ror64(tmp, 53);
	b12 -= b3;

	tmp = b7 ^ b10;
	b7 = ror64(tmp, 4);
	b10 -= b7;

	tmp = b15 ^ b4;
	b15 = ror64(tmp, 51);
	b4 -= b15;

	tmp = b11 ^ b6;
	b11 = ror64(tmp, 56);
	b6 -= b11;

	tmp = b13 ^ b2;
	b13 = ror64(tmp, 34);
	b2 -= b13;

	tmp = b9 ^ b0;
	b9 = ror64(tmp, 16);
	b0 -= b9;

	tmp = b15 ^ b14;
	b15 = ror64(tmp, 30);
	b14 -= b15 + k8 + t0;
	b15 -= k9 + 11;

	tmp = b13 ^ b12;
	b13 = ror64(tmp, 44);
	b12 -= b13 + k6;
	b13 -= k7 + t2;

	tmp = b11 ^ b10;
	b11 = ror64(tmp, 47);
	b10 -= b11 + k4;
	b11 -= k5;

	tmp = b9 ^ b8;
	b9 = ror64(tmp, 12);
	b8 -= b9 + k2;
	b9 -= k3;

	tmp = b7 ^ b6;
	b7 = ror64(tmp, 31);
	b6 -= b7 + k0;
	b7 -= k1;

	tmp = b5 ^ b4;
	b5 = ror64(tmp, 37);
	b4 -= b5 + k15;
	b5 -= k16;

	tmp = b3 ^ b2;
	b3 = ror64(tmp, 9);
	b2 -= b3 + k13;
	b3 -= k14;

	tmp = b1 ^ b0;
	b1 = ror64(tmp, 41);
	b0 -= b1 + k11;
	b1 -= k12;

	tmp = b7 ^ b12;
	b7 = ror64(tmp, 25);
	b12 -= b7;

	tmp = b3 ^ b10;
	b3 = ror64(tmp, 16);
	b10 -= b3;

	tmp = b5 ^ b8;
	b5 = ror64(tmp, 28);
	b8 -= b5;

	tmp = b1 ^ b14;
	b1 = ror64(tmp, 47);
	b14 -= b1;

	tmp = b9 ^ b4;
	b9 = ror64(tmp, 41);
	b4 -= b9;

	tmp = b13 ^ b6;
	b13 = ror64(tmp, 48);
	b6 -= b13;

	tmp = b11 ^ b2;
	b11 = ror64(tmp, 20);
	b2 -= b11;

	tmp = b15 ^ b0;
	b15 = ror64(tmp, 5);
	b0 -= b15;

	tmp = b9 ^ b10;
	b9 = ror64(tmp, 17);
	b10 -= b9;

	tmp = b11 ^ b8;
	b11 = ror64(tmp, 59);
	b8 -= b11;

	tmp = b13 ^ b14;
	b13 = ror64(tmp, 41);
	b14 -= b13;

	tmp = b15 ^ b12;
	b15 = ror64(tmp, 34);
	b12 -= b15;

	tmp = b1 ^ b6;
	b1 = ror64(tmp, 13);
	b6 -= b1;

	tmp = b3 ^ b4;
	b3 = ror64(tmp, 51);
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = ror64(tmp, 4);
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = ror64(tmp, 33);
	b0 -= b7;

	tmp = b1 ^ b8;
	b1 = ror64(tmp, 52);
	b8 -= b1;

	tmp = b5 ^ b14;
	b5 = ror64(tmp, 23);
	b14 -= b5;

	tmp = b3 ^ b12;
	b3 = ror64(tmp, 18);
	b12 -= b3;

	tmp = b7 ^ b10;
	b7 = ror64(tmp, 49);
	b10 -= b7;

	tmp = b15 ^ b4;
	b15 = ror64(tmp, 55);
	b4 -= b15;

	tmp = b11 ^ b6;
	b11 = ror64(tmp, 10);
	b6 -= b11;

	tmp = b13 ^ b2;
	b13 = ror64(tmp, 19);
	b2 -= b13;

	tmp = b9 ^ b0;
	b9 = ror64(tmp, 38);
	b0 -= b9;

	tmp = b15 ^ b14;
	b15 = ror64(tmp, 37);
	b14 -= b15 + k7 + t2;
	b15 -= k8 + 10;

	tmp = b13 ^ b12;
	b13 = ror64(tmp, 22);
	b12 -= b13 + k5;
	b13 -= k6 + t1;

	tmp = b11 ^ b10;
	b11 = ror64(tmp, 17);
	b10 -= b11 + k3;
	b11 -= k4;

	tmp = b9 ^ b8;
	b9 = ror64(tmp, 8);
	b8 -= b9 + k1;
	b9 -= k2;

	tmp = b7 ^ b6;
	b7 = ror64(tmp, 47);
	b6 -= b7 + k16;
	b7 -= k0;

	tmp = b5 ^ b4;
	b5 = ror64(tmp, 8);
	b4 -= b5 + k14;
	b5 -= k15;

	tmp = b3 ^ b2;
	b3 = ror64(tmp, 13);
	b2 -= b3 + k12;
	b3 -= k13;

	tmp = b1 ^ b0;
	b1 = ror64(tmp, 24);
	b0 -= b1 + k10;
	b1 -= k11;

	tmp = b7 ^ b12;
	b7 = ror64(tmp, 20);
	b12 -= b7;

	tmp = b3 ^ b10;
	b3 = ror64(tmp, 37);
	b10 -= b3;

	tmp = b5 ^ b8;
	b5 = ror64(tmp, 31);
	b8 -= b5;

	tmp = b1 ^ b14;
	b1 = ror64(tmp, 23);
	b14 -= b1;

	tmp = b9 ^ b4;
	b9 = ror64(tmp, 52);
	b4 -= b9;

	tmp = b13 ^ b6;
	b13 = ror64(tmp, 35);
	b6 -= b13;

	tmp = b11 ^ b2;
	b11 = ror64(tmp, 48);
	b2 -= b11;

	tmp = b15 ^ b0;
	b15 = ror64(tmp, 9);
	b0 -= b15;

	tmp = b9 ^ b10;
	b9 = ror64(tmp, 25);
	b10 -= b9;

	tmp = b11 ^ b8;
	b11 = ror64(tmp, 44);
	b8 -= b11;

	tmp = b13 ^ b14;
	b13 = ror64(tmp, 42);
	b14 -= b13;

	tmp = b15 ^ b12;
	b15 = ror64(tmp, 19);
	b12 -= b15;

	tmp = b1 ^ b6;
	b1 = ror64(tmp, 46);
	b6 -= b1;

	tmp = b3 ^ b4;
	b3 = ror64(tmp, 47);
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = ror64(tmp, 44);
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = ror64(tmp, 31);
	b0 -= b7;

	tmp = b1 ^ b8;
	b1 = ror64(tmp, 41);
	b8 -= b1;

	tmp = b5 ^ b14;
	b5 = ror64(tmp, 42);
	b14 -= b5;

	tmp = b3 ^ b12;
	b3 = ror64(tmp, 53);
	b12 -= b3;

	tmp = b7 ^ b10;
	b7 = ror64(tmp, 4);
	b10 -= b7;

	tmp = b15 ^ b4;
	b15 = ror64(tmp, 51);
	b4 -= b15;

	tmp = b11 ^ b6;
	b11 = ror64(tmp, 56);
	b6 -= b11;

	tmp = b13 ^ b2;
	b13 = ror64(tmp, 34);
	b2 -= b13;

	tmp = b9 ^ b0;
	b9 = ror64(tmp, 16);
	b0 -= b9;

	tmp = b15 ^ b14;
	b15 = ror64(tmp, 30);
	b14 -= b15 + k6 + t1;
	b15 -= k7 + 9;

	tmp = b13 ^ b12;
	b13 = ror64(tmp, 44);
	b12 -= b13 + k4;
	b13 -= k5 + t0;

	tmp = b11 ^ b10;
	b11 = ror64(tmp, 47);
	b10 -= b11 + k2;
	b11 -= k3;

	tmp = b9 ^ b8;
	b9 = ror64(tmp, 12);
	b8 -= b9 + k0;
	b9 -= k1;

	tmp = b7 ^ b6;
	b7 = ror64(tmp, 31);
	b6 -= b7 + k15;
	b7 -= k16;

	tmp = b5 ^ b4;
	b5 = ror64(tmp, 37);
	b4 -= b5 + k13;
	b5 -= k14;

	tmp = b3 ^ b2;
	b3 = ror64(tmp, 9);
	b2 -= b3 + k11;
	b3 -= k12;

	tmp = b1 ^ b0;
	b1 = ror64(tmp, 41);
	b0 -= b1 + k9;
	b1 -= k10;

	tmp = b7 ^ b12;
	b7 = ror64(tmp, 25);
	b12 -= b7;

	tmp = b3 ^ b10;
	b3 = ror64(tmp, 16);
	b10 -= b3;

	tmp = b5 ^ b8;
	b5 = ror64(tmp, 28);
	b8 -= b5;

	tmp = b1 ^ b14;
	b1 = ror64(tmp, 47);
	b14 -= b1;

	tmp = b9 ^ b4;
	b9 = ror64(tmp, 41);
	b4 -= b9;

	tmp = b13 ^ b6;
	b13 = ror64(tmp, 48);
	b6 -= b13;

	tmp = b11 ^ b2;
	b11 = ror64(tmp, 20);
	b2 -= b11;

	tmp = b15 ^ b0;
	b15 = ror64(tmp, 5);
	b0 -= b15;

	tmp = b9 ^ b10;
	b9 = ror64(tmp, 17);
	b10 -= b9;

	tmp = b11 ^ b8;
	b11 = ror64(tmp, 59);
	b8 -= b11;

	tmp = b13 ^ b14;
	b13 = ror64(tmp, 41);
	b14 -= b13;

	tmp = b15 ^ b12;
	b15 = ror64(tmp, 34);
	b12 -= b15;

	tmp = b1 ^ b6;
	b1 = ror64(tmp, 13);
	b6 -= b1;

	tmp = b3 ^ b4;
	b3 = ror64(tmp, 51);
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = ror64(tmp, 4);
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = ror64(tmp, 33);
	b0 -= b7;

	tmp = b1 ^ b8;
	b1 = ror64(tmp, 52);
	b8 -= b1;

	tmp = b5 ^ b14;
	b5 = ror64(tmp, 23);
	b14 -= b5;

	tmp = b3 ^ b12;
	b3 = ror64(tmp, 18);
	b12 -= b3;

	tmp = b7 ^ b10;
	b7 = ror64(tmp, 49);
	b10 -= b7;

	tmp = b15 ^ b4;
	b15 = ror64(tmp, 55);
	b4 -= b15;

	tmp = b11 ^ b6;
	b11 = ror64(tmp, 10);
	b6 -= b11;

	tmp = b13 ^ b2;
	b13 = ror64(tmp, 19);
	b2 -= b13;

	tmp = b9 ^ b0;
	b9 = ror64(tmp, 38);
	b0 -= b9;

	tmp = b15 ^ b14;
	b15 = ror64(tmp, 37);
	b14 -= b15 + k5 + t0;
	b15 -= k6 + 8;

	tmp = b13 ^ b12;
	b13 = ror64(tmp, 22);
	b12 -= b13 + k3;
	b13 -= k4 + t2;

	tmp = b11 ^ b10;
	b11 = ror64(tmp, 17);
	b10 -= b11 + k1;
	b11 -= k2;

	tmp = b9 ^ b8;
	b9 = ror64(tmp, 8);
	b8 -= b9 + k16;
	b9 -= k0;

	tmp = b7 ^ b6;
	b7 = ror64(tmp, 47);
	b6 -= b7 + k14;
	b7 -= k15;

	tmp = b5 ^ b4;
	b5 = ror64(tmp, 8);
	b4 -= b5 + k12;
	b5 -= k13;

	tmp = b3 ^ b2;
	b3 = ror64(tmp, 13);
	b2 -= b3 + k10;
	b3 -= k11;

	tmp = b1 ^ b0;
	b1 = ror64(tmp, 24);
	b0 -= b1 + k8;
	b1 -= k9;

	tmp = b7 ^ b12;
	b7 = ror64(tmp, 20);
	b12 -= b7;

	tmp = b3 ^ b10;
	b3 = ror64(tmp, 37);
	b10 -= b3;

	tmp = b5 ^ b8;
	b5 = ror64(tmp, 31);
	b8 -= b5;

	tmp = b1 ^ b14;
	b1 = ror64(tmp, 23);
	b14 -= b1;

	tmp = b9 ^ b4;
	b9 = ror64(tmp, 52);
	b4 -= b9;

	tmp = b13 ^ b6;
	b13 = ror64(tmp, 35);
	b6 -= b13;

	tmp = b11 ^ b2;
	b11 = ror64(tmp, 48);
	b2 -= b11;

	tmp = b15 ^ b0;
	b15 = ror64(tmp, 9);
	b0 -= b15;

	tmp = b9 ^ b10;
	b9 = ror64(tmp, 25);
	b10 -= b9;

	tmp = b11 ^ b8;
	b11 = ror64(tmp, 44);
	b8 -= b11;

	tmp = b13 ^ b14;
	b13 = ror64(tmp, 42);
	b14 -= b13;

	tmp = b15 ^ b12;
	b15 = ror64(tmp, 19);
	b12 -= b15;

	tmp = b1 ^ b6;
	b1 = ror64(tmp, 46);
	b6 -= b1;

	tmp = b3 ^ b4;
	b3 = ror64(tmp, 47);
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = ror64(tmp, 44);
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = ror64(tmp, 31);
	b0 -= b7;

	tmp = b1 ^ b8;
	b1 = ror64(tmp, 41);
	b8 -= b1;

	tmp = b5 ^ b14;
	b5 = ror64(tmp, 42);
	b14 -= b5;

	tmp = b3 ^ b12;
	b3 = ror64(tmp, 53);
	b12 -= b3;

	tmp = b7 ^ b10;
	b7 = ror64(tmp, 4);
	b10 -= b7;

	tmp = b15 ^ b4;
	b15 = ror64(tmp, 51);
	b4 -= b15;

	tmp = b11 ^ b6;
	b11 = ror64(tmp, 56);
	b6 -= b11;

	tmp = b13 ^ b2;
	b13 = ror64(tmp, 34);
	b2 -= b13;

	tmp = b9 ^ b0;
	b9 = ror64(tmp, 16);
	b0 -= b9;

	tmp = b15 ^ b14;
	b15 = ror64(tmp, 30);
	b14 -= b15 + k4 + t2;
	b15 -= k5 + 7;

	tmp = b13 ^ b12;
	b13 = ror64(tmp, 44);
	b12 -= b13 + k2;
	b13 -= k3 + t1;

	tmp = b11 ^ b10;
	b11 = ror64(tmp, 47);
	b10 -= b11 + k0;
	b11 -= k1;

	tmp = b9 ^ b8;
	b9 = ror64(tmp, 12);
	b8 -= b9 + k15;
	b9 -= k16;

	tmp = b7 ^ b6;
	b7 = ror64(tmp, 31);
	b6 -= b7 + k13;
	b7 -= k14;

	tmp = b5 ^ b4;
	b5 = ror64(tmp, 37);
	b4 -= b5 + k11;
	b5 -= k12;

	tmp = b3 ^ b2;
	b3 = ror64(tmp, 9);
	b2 -= b3 + k9;
	b3 -= k10;

	tmp = b1 ^ b0;
	b1 = ror64(tmp, 41);
	b0 -= b1 + k7;
	b1 -= k8;

	tmp = b7 ^ b12;
	b7 = ror64(tmp, 25);
	b12 -= b7;

	tmp = b3 ^ b10;
	b3 = ror64(tmp, 16);
	b10 -= b3;

	tmp = b5 ^ b8;
	b5 = ror64(tmp, 28);
	b8 -= b5;

	tmp = b1 ^ b14;
	b1 = ror64(tmp, 47);
	b14 -= b1;

	tmp = b9 ^ b4;
	b9 = ror64(tmp, 41);
	b4 -= b9;

	tmp = b13 ^ b6;
	b13 = ror64(tmp, 48);
	b6 -= b13;

	tmp = b11 ^ b2;
	b11 = ror64(tmp, 20);
	b2 -= b11;

	tmp = b15 ^ b0;
	b15 = ror64(tmp, 5);
	b0 -= b15;

	tmp = b9 ^ b10;
	b9 = ror64(tmp, 17);
	b10 -= b9;

	tmp = b11 ^ b8;
	b11 = ror64(tmp, 59);
	b8 -= b11;

	tmp = b13 ^ b14;
	b13 = ror64(tmp, 41);
	b14 -= b13;

	tmp = b15 ^ b12;
	b15 = ror64(tmp, 34);
	b12 -= b15;

	tmp = b1 ^ b6;
	b1 = ror64(tmp, 13);
	b6 -= b1;

	tmp = b3 ^ b4;
	b3 = ror64(tmp, 51);
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = ror64(tmp, 4);
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = ror64(tmp, 33);
	b0 -= b7;

	tmp = b1 ^ b8;
	b1 = ror64(tmp, 52);
	b8 -= b1;

	tmp = b5 ^ b14;
	b5 = ror64(tmp, 23);
	b14 -= b5;

	tmp = b3 ^ b12;
	b3 = ror64(tmp, 18);
	b12 -= b3;

	tmp = b7 ^ b10;
	b7 = ror64(tmp, 49);
	b10 -= b7;

	tmp = b15 ^ b4;
	b15 = ror64(tmp, 55);
	b4 -= b15;

	tmp = b11 ^ b6;
	b11 = ror64(tmp, 10);
	b6 -= b11;

	tmp = b13 ^ b2;
	b13 = ror64(tmp, 19);
	b2 -= b13;

	tmp = b9 ^ b0;
	b9 = ror64(tmp, 38);
	b0 -= b9;

	tmp = b15 ^ b14;
	b15 = ror64(tmp, 37);
	b14 -= b15 + k3 + t1;
	b15 -= k4 + 6;

	tmp = b13 ^ b12;
	b13 = ror64(tmp, 22);
	b12 -= b13 + k1;
	b13 -= k2 + t0;

	tmp = b11 ^ b10;
	b11 = ror64(tmp, 17);
	b10 -= b11 + k16;
	b11 -= k0;

	tmp = b9 ^ b8;
	b9 = ror64(tmp, 8);
	b8 -= b9 + k14;
	b9 -= k15;

	tmp = b7 ^ b6;
	b7 = ror64(tmp, 47);
	b6 -= b7 + k12;
	b7 -= k13;

	tmp = b5 ^ b4;
	b5 = ror64(tmp, 8);
	b4 -= b5 + k10;
	b5 -= k11;

	tmp = b3 ^ b2;
	b3 = ror64(tmp, 13);
	b2 -= b3 + k8;
	b3 -= k9;

	tmp = b1 ^ b0;
	b1 = ror64(tmp, 24);
	b0 -= b1 + k6;
	b1 -= k7;

	tmp = b7 ^ b12;
	b7 = ror64(tmp, 20);
	b12 -= b7;

	tmp = b3 ^ b10;
	b3 = ror64(tmp, 37);
	b10 -= b3;

	tmp = b5 ^ b8;
	b5 = ror64(tmp, 31);
	b8 -= b5;

	tmp = b1 ^ b14;
	b1 = ror64(tmp, 23);
	b14 -= b1;

	tmp = b9 ^ b4;
	b9 = ror64(tmp, 52);
	b4 -= b9;

	tmp = b13 ^ b6;
	b13 = ror64(tmp, 35);
	b6 -= b13;

	tmp = b11 ^ b2;
	b11 = ror64(tmp, 48);
	b2 -= b11;

	tmp = b15 ^ b0;
	b15 = ror64(tmp, 9);
	b0 -= b15;

	tmp = b9 ^ b10;
	b9 = ror64(tmp, 25);
	b10 -= b9;

	tmp = b11 ^ b8;
	b11 = ror64(tmp, 44);
	b8 -= b11;

	tmp = b13 ^ b14;
	b13 = ror64(tmp, 42);
	b14 -= b13;

	tmp = b15 ^ b12;
	b15 = ror64(tmp, 19);
	b12 -= b15;

	tmp = b1 ^ b6;
	b1 = ror64(tmp, 46);
	b6 -= b1;

	tmp = b3 ^ b4;
	b3 = ror64(tmp, 47);
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = ror64(tmp, 44);
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = ror64(tmp, 31);
	b0 -= b7;

	tmp = b1 ^ b8;
	b1 = ror64(tmp, 41);
	b8 -= b1;

	tmp = b5 ^ b14;
	b5 = ror64(tmp, 42);
	b14 -= b5;

	tmp = b3 ^ b12;
	b3 = ror64(tmp, 53);
	b12 -= b3;

	tmp = b7 ^ b10;
	b7 = ror64(tmp, 4);
	b10 -= b7;

	tmp = b15 ^ b4;
	b15 = ror64(tmp, 51);
	b4 -= b15;

	tmp = b11 ^ b6;
	b11 = ror64(tmp, 56);
	b6 -= b11;

	tmp = b13 ^ b2;
	b13 = ror64(tmp, 34);
	b2 -= b13;

	tmp = b9 ^ b0;
	b9 = ror64(tmp, 16);
	b0 -= b9;

	tmp = b15 ^ b14;
	b15 = ror64(tmp, 30);
	b14 -= b15 + k2 + t0;
	b15 -= k3 + 5;

	tmp = b13 ^ b12;
	b13 = ror64(tmp, 44);
	b12 -= b13 + k0;
	b13 -= k1 + t2;

	tmp = b11 ^ b10;
	b11 = ror64(tmp, 47);
	b10 -= b11 + k15;
	b11 -= k16;

	tmp = b9 ^ b8;
	b9 = ror64(tmp, 12);
	b8 -= b9 + k13;
	b9 -= k14;

	tmp = b7 ^ b6;
	b7 = ror64(tmp, 31);
	b6 -= b7 + k11;
	b7 -= k12;

	tmp = b5 ^ b4;
	b5 = ror64(tmp, 37);
	b4 -= b5 + k9;
	b5 -= k10;

	tmp = b3 ^ b2;
	b3 = ror64(tmp, 9);
	b2 -= b3 + k7;
	b3 -= k8;

	tmp = b1 ^ b0;
	b1 = ror64(tmp, 41);
	b0 -= b1 + k5;
	b1 -= k6;

	tmp = b7 ^ b12;
	b7 = ror64(tmp, 25);
	b12 -= b7;

	tmp = b3 ^ b10;
	b3 = ror64(tmp, 16);
	b10 -= b3;

	tmp = b5 ^ b8;
	b5 = ror64(tmp, 28);
	b8 -= b5;

	tmp = b1 ^ b14;
	b1 = ror64(tmp, 47);
	b14 -= b1;

	tmp = b9 ^ b4;
	b9 = ror64(tmp, 41);
	b4 -= b9;

	tmp = b13 ^ b6;
	b13 = ror64(tmp, 48);
	b6 -= b13;

	tmp = b11 ^ b2;
	b11 = ror64(tmp, 20);
	b2 -= b11;

	tmp = b15 ^ b0;
	b15 = ror64(tmp, 5);
	b0 -= b15;

	tmp = b9 ^ b10;
	b9 = ror64(tmp, 17);
	b10 -= b9;

	tmp = b11 ^ b8;
	b11 = ror64(tmp, 59);
	b8 -= b11;

	tmp = b13 ^ b14;
	b13 = ror64(tmp, 41);
	b14 -= b13;

	tmp = b15 ^ b12;
	b15 = ror64(tmp, 34);
	b12 -= b15;

	tmp = b1 ^ b6;
	b1 = ror64(tmp, 13);
	b6 -= b1;

	tmp = b3 ^ b4;
	b3 = ror64(tmp, 51);
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = ror64(tmp, 4);
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = ror64(tmp, 33);
	b0 -= b7;

	tmp = b1 ^ b8;
	b1 = ror64(tmp, 52);
	b8 -= b1;

	tmp = b5 ^ b14;
	b5 = ror64(tmp, 23);
	b14 -= b5;

	tmp = b3 ^ b12;
	b3 = ror64(tmp, 18);
	b12 -= b3;

	tmp = b7 ^ b10;
	b7 = ror64(tmp, 49);
	b10 -= b7;

	tmp = b15 ^ b4;
	b15 = ror64(tmp, 55);
	b4 -= b15;

	tmp = b11 ^ b6;
	b11 = ror64(tmp, 10);
	b6 -= b11;

	tmp = b13 ^ b2;
	b13 = ror64(tmp, 19);
	b2 -= b13;

	tmp = b9 ^ b0;
	b9 = ror64(tmp, 38);
	b0 -= b9;

	tmp = b15 ^ b14;
	b15 = ror64(tmp, 37);
	b14 -= b15 + k1 + t2;
	b15 -= k2 + 4;

	tmp = b13 ^ b12;
	b13 = ror64(tmp, 22);
	b12 -= b13 + k16;
	b13 -= k0 + t1;

	tmp = b11 ^ b10;
	b11 = ror64(tmp, 17);
	b10 -= b11 + k14;
	b11 -= k15;

	tmp = b9 ^ b8;
	b9 = ror64(tmp, 8);
	b8 -= b9 + k12;
	b9 -= k13;

	tmp = b7 ^ b6;
	b7 = ror64(tmp, 47);
	b6 -= b7 + k10;
	b7 -= k11;

	tmp = b5 ^ b4;
	b5 = ror64(tmp, 8);
	b4 -= b5 + k8;
	b5 -= k9;

	tmp = b3 ^ b2;
	b3 = ror64(tmp, 13);
	b2 -= b3 + k6;
	b3 -= k7;

	tmp = b1 ^ b0;
	b1 = ror64(tmp, 24);
	b0 -= b1 + k4;
	b1 -= k5;

	tmp = b7 ^ b12;
	b7 = ror64(tmp, 20);
	b12 -= b7;

	tmp = b3 ^ b10;
	b3 = ror64(tmp, 37);
	b10 -= b3;

	tmp = b5 ^ b8;
	b5 = ror64(tmp, 31);
	b8 -= b5;

	tmp = b1 ^ b14;
	b1 = ror64(tmp, 23);
	b14 -= b1;

	tmp = b9 ^ b4;
	b9 = ror64(tmp, 52);
	b4 -= b9;

	tmp = b13 ^ b6;
	b13 = ror64(tmp, 35);
	b6 -= b13;

	tmp = b11 ^ b2;
	b11 = ror64(tmp, 48);
	b2 -= b11;

	tmp = b15 ^ b0;
	b15 = ror64(tmp, 9);
	b0 -= b15;

	tmp = b9 ^ b10;
	b9 = ror64(tmp, 25);
	b10 -= b9;

	tmp = b11 ^ b8;
	b11 = ror64(tmp, 44);
	b8 -= b11;

	tmp = b13 ^ b14;
	b13 = ror64(tmp, 42);
	b14 -= b13;

	tmp = b15 ^ b12;
	b15 = ror64(tmp, 19);
	b12 -= b15;

	tmp = b1 ^ b6;
	b1 = ror64(tmp, 46);
	b6 -= b1;

	tmp = b3 ^ b4;
	b3 = ror64(tmp, 47);
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = ror64(tmp, 44);
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = ror64(tmp, 31);
	b0 -= b7;

	tmp = b1 ^ b8;
	b1 = ror64(tmp, 41);
	b8 -= b1;

	tmp = b5 ^ b14;
	b5 = ror64(tmp, 42);
	b14 -= b5;

	tmp = b3 ^ b12;
	b3 = ror64(tmp, 53);
	b12 -= b3;

	tmp = b7 ^ b10;
	b7 = ror64(tmp, 4);
	b10 -= b7;

	tmp = b15 ^ b4;
	b15 = ror64(tmp, 51);
	b4 -= b15;

	tmp = b11 ^ b6;
	b11 = ror64(tmp, 56);
	b6 -= b11;

	tmp = b13 ^ b2;
	b13 = ror64(tmp, 34);
	b2 -= b13;

	tmp = b9 ^ b0;
	b9 = ror64(tmp, 16);
	b0 -= b9;

	tmp = b15 ^ b14;
	b15 = ror64(tmp, 30);
	b14 -= b15 + k0 + t1;
	b15 -= k1 + 3;

	tmp = b13 ^ b12;
	b13 = ror64(tmp, 44);
	b12 -= b13 + k15;
	b13 -= k16 + t0;

	tmp = b11 ^ b10;
	b11 = ror64(tmp, 47);
	b10 -= b11 + k13;
	b11 -= k14;

	tmp = b9 ^ b8;
	b9 = ror64(tmp, 12);
	b8 -= b9 + k11;
	b9 -= k12;

	tmp = b7 ^ b6;
	b7 = ror64(tmp, 31);
	b6 -= b7 + k9;
	b7 -= k10;

	tmp = b5 ^ b4;
	b5 = ror64(tmp, 37);
	b4 -= b5 + k7;
	b5 -= k8;

	tmp = b3 ^ b2;
	b3 = ror64(tmp, 9);
	b2 -= b3 + k5;
	b3 -= k6;

	tmp = b1 ^ b0;
	b1 = ror64(tmp, 41);
	b0 -= b1 + k3;
	b1 -= k4;

	tmp = b7 ^ b12;
	b7 = ror64(tmp, 25);
	b12 -= b7;

	tmp = b3 ^ b10;
	b3 = ror64(tmp, 16);
	b10 -= b3;

	tmp = b5 ^ b8;
	b5 = ror64(tmp, 28);
	b8 -= b5;

	tmp = b1 ^ b14;
	b1 = ror64(tmp, 47);
	b14 -= b1;

	tmp = b9 ^ b4;
	b9 = ror64(tmp, 41);
	b4 -= b9;

	tmp = b13 ^ b6;
	b13 = ror64(tmp, 48);
	b6 -= b13;

	tmp = b11 ^ b2;
	b11 = ror64(tmp, 20);
	b2 -= b11;

	tmp = b15 ^ b0;
	b15 = ror64(tmp, 5);
	b0 -= b15;

	tmp = b9 ^ b10;
	b9 = ror64(tmp, 17);
	b10 -= b9;

	tmp = b11 ^ b8;
	b11 = ror64(tmp, 59);
	b8 -= b11;

	tmp = b13 ^ b14;
	b13 = ror64(tmp, 41);
	b14 -= b13;

	tmp = b15 ^ b12;
	b15 = ror64(tmp, 34);
	b12 -= b15;

	tmp = b1 ^ b6;
	b1 = ror64(tmp, 13);
	b6 -= b1;

	tmp = b3 ^ b4;
	b3 = ror64(tmp, 51);
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = ror64(tmp, 4);
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = ror64(tmp, 33);
	b0 -= b7;

	tmp = b1 ^ b8;
	b1 = ror64(tmp, 52);
	b8 -= b1;

	tmp = b5 ^ b14;
	b5 = ror64(tmp, 23);
	b14 -= b5;

	tmp = b3 ^ b12;
	b3 = ror64(tmp, 18);
	b12 -= b3;

	tmp = b7 ^ b10;
	b7 = ror64(tmp, 49);
	b10 -= b7;

	tmp = b15 ^ b4;
	b15 = ror64(tmp, 55);
	b4 -= b15;

	tmp = b11 ^ b6;
	b11 = ror64(tmp, 10);
	b6 -= b11;

	tmp = b13 ^ b2;
	b13 = ror64(tmp, 19);
	b2 -= b13;

	tmp = b9 ^ b0;
	b9 = ror64(tmp, 38);
	b0 -= b9;

	tmp = b15 ^ b14;
	b15 = ror64(tmp, 37);
	b14 -= b15 + k16 + t0;
	b15 -= k0 + 2;

	tmp = b13 ^ b12;
	b13 = ror64(tmp, 22);
	b12 -= b13 + k14;
	b13 -= k15 + t2;

	tmp = b11 ^ b10;
	b11 = ror64(tmp, 17);
	b10 -= b11 + k12;
	b11 -= k13;

	tmp = b9 ^ b8;
	b9 = ror64(tmp, 8);
	b8 -= b9 + k10;
	b9 -= k11;

	tmp = b7 ^ b6;
	b7 = ror64(tmp, 47);
	b6 -= b7 + k8;
	b7 -= k9;

	tmp = b5 ^ b4;
	b5 = ror64(tmp, 8);
	b4 -= b5 + k6;
	b5 -= k7;

	tmp = b3 ^ b2;
	b3 = ror64(tmp, 13);
	b2 -= b3 + k4;
	b3 -= k5;

	tmp = b1 ^ b0;
	b1 = ror64(tmp, 24);
	b0 -= b1 + k2;
	b1 -= k3;

	tmp = b7 ^ b12;
	b7 = ror64(tmp, 20);
	b12 -= b7;

	tmp = b3 ^ b10;
	b3 = ror64(tmp, 37);
	b10 -= b3;

	tmp = b5 ^ b8;
	b5 = ror64(tmp, 31);
	b8 -= b5;

	tmp = b1 ^ b14;
	b1 = ror64(tmp, 23);
	b14 -= b1;

	tmp = b9 ^ b4;
	b9 = ror64(tmp, 52);
	b4 -= b9;

	tmp = b13 ^ b6;
	b13 = ror64(tmp, 35);
	b6 -= b13;

	tmp = b11 ^ b2;
	b11 = ror64(tmp, 48);
	b2 -= b11;

	tmp = b15 ^ b0;
	b15 = ror64(tmp, 9);
	b0 -= b15;

	tmp = b9 ^ b10;
	b9 = ror64(tmp, 25);
	b10 -= b9;

	tmp = b11 ^ b8;
	b11 = ror64(tmp, 44);
	b8 -= b11;

	tmp = b13 ^ b14;
	b13 = ror64(tmp, 42);
	b14 -= b13;

	tmp = b15 ^ b12;
	b15 = ror64(tmp, 19);
	b12 -= b15;

	tmp = b1 ^ b6;
	b1 = ror64(tmp, 46);
	b6 -= b1;

	tmp = b3 ^ b4;
	b3 = ror64(tmp, 47);
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = ror64(tmp, 44);
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = ror64(tmp, 31);
	b0 -= b7;

	tmp = b1 ^ b8;
	b1 = ror64(tmp, 41);
	b8 -= b1;

	tmp = b5 ^ b14;
	b5 = ror64(tmp, 42);
	b14 -= b5;

	tmp = b3 ^ b12;
	b3 = ror64(tmp, 53);
	b12 -= b3;

	tmp = b7 ^ b10;
	b7 = ror64(tmp, 4);
	b10 -= b7;

	tmp = b15 ^ b4;
	b15 = ror64(tmp, 51);
	b4 -= b15;

	tmp = b11 ^ b6;
	b11 = ror64(tmp, 56);
	b6 -= b11;

	tmp = b13 ^ b2;
	b13 = ror64(tmp, 34);
	b2 -= b13;

	tmp = b9 ^ b0;
	b9 = ror64(tmp, 16);
	b0 -= b9;

	tmp = b15 ^ b14;
	b15 = ror64(tmp, 30);
	b14 -= b15 + k15 + t2;
	b15 -= k16 + 1;

	tmp = b13 ^ b12;
	b13 = ror64(tmp, 44);
	b12 -= b13 + k13;
	b13 -= k14 + t1;

	tmp = b11 ^ b10;
	b11 = ror64(tmp, 47);
	b10 -= b11 + k11;
	b11 -= k12;

	tmp = b9 ^ b8;
	b9 = ror64(tmp, 12);
	b8 -= b9 + k9;
	b9 -= k10;

	tmp = b7 ^ b6;
	b7 = ror64(tmp, 31);
	b6 -= b7 + k7;
	b7 -= k8;

	tmp = b5 ^ b4;
	b5 = ror64(tmp, 37);
	b4 -= b5 + k5;
	b5 -= k6;

	tmp = b3 ^ b2;
	b3 = ror64(tmp, 9);
	b2 -= b3 + k3;
	b3 -= k4;

	tmp = b1 ^ b0;
	b1 = ror64(tmp, 41);
	b0 -= b1 + k1;
	b1 -= k2;

	tmp = b7 ^ b12;
	b7 = ror64(tmp, 25);
	b12 -= b7;

	tmp = b3 ^ b10;
	b3 = ror64(tmp, 16);
	b10 -= b3;

	tmp = b5 ^ b8;
	b5 = ror64(tmp, 28);
	b8 -= b5;

	tmp = b1 ^ b14;
	b1 = ror64(tmp, 47);
	b14 -= b1;

	tmp = b9 ^ b4;
	b9 = ror64(tmp, 41);
	b4 -= b9;

	tmp = b13 ^ b6;
	b13 = ror64(tmp, 48);
	b6 -= b13;

	tmp = b11 ^ b2;
	b11 = ror64(tmp, 20);
	b2 -= b11;

	tmp = b15 ^ b0;
	b15 = ror64(tmp, 5);
	b0 -= b15;

	tmp = b9 ^ b10;
	b9 = ror64(tmp, 17);
	b10 -= b9;

	tmp = b11 ^ b8;
	b11 = ror64(tmp, 59);
	b8 -= b11;

	tmp = b13 ^ b14;
	b13 = ror64(tmp, 41);
	b14 -= b13;

	tmp = b15 ^ b12;
	b15 = ror64(tmp, 34);
	b12 -= b15;

	tmp = b1 ^ b6;
	b1 = ror64(tmp, 13);
	b6 -= b1;

	tmp = b3 ^ b4;
	b3 = ror64(tmp, 51);
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = ror64(tmp, 4);
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = ror64(tmp, 33);
	b0 -= b7;

	tmp = b1 ^ b8;
	b1 = ror64(tmp, 52);
	b8 -= b1;

	tmp = b5 ^ b14;
	b5 = ror64(tmp, 23);
	b14 -= b5;

	tmp = b3 ^ b12;
	b3 = ror64(tmp, 18);
	b12 -= b3;

	tmp = b7 ^ b10;
	b7 = ror64(tmp, 49);
	b10 -= b7;

	tmp = b15 ^ b4;
	b15 = ror64(tmp, 55);
	b4 -= b15;

	tmp = b11 ^ b6;
	b11 = ror64(tmp, 10);
	b6 -= b11;

	tmp = b13 ^ b2;
	b13 = ror64(tmp, 19);
	b2 -= b13;

	tmp = b9 ^ b0;
	b9 = ror64(tmp, 38);
	b0 -= b9;

	tmp = b15 ^ b14;
	b15 = ror64(tmp, 37);
	b14 -= b15 + k14 + t1;
	b15 -= k15;

	tmp = b13 ^ b12;
	b13 = ror64(tmp, 22);
	b12 -= b13 + k12;
	b13 -= k13 + t0;

	tmp = b11 ^ b10;
	b11 = ror64(tmp, 17);
	b10 -= b11 + k10;
	b11 -= k11;

	tmp = b9 ^ b8;
	b9 = ror64(tmp, 8);
	b8 -= b9 + k8;
	b9 -= k9;

	tmp = b7 ^ b6;
	b7 = ror64(tmp, 47);
	b6 -= b7 + k6;
	b7 -= k7;

	tmp = b5 ^ b4;
	b5 = ror64(tmp, 8);
	b4 -= b5 + k4;
	b5 -= k5;

	tmp = b3 ^ b2;
	b3 = ror64(tmp, 13);
	b2 -= b3 + k2;
	b3 -= k3;

	tmp = b1 ^ b0;
	b1 = ror64(tmp, 24);
	b0 -= b1 + k0;
	b1 -= k1;

	output[15] = b15;
	output[14] = b14;
	output[13] = b13;
	output[12] = b12;
	output[11] = b11;
	output[10] = b10;
	output[9] = b9;
	output[8] = b8;
	output[7] = b7;
	output[6] = b6;
	output[5] = b5;
	output[4] = b4;
	output[3] = b3;
	output[2] = b2;
	output[1] = b1;
	output[0] = b0;
}

#undef t0
#undef t1
#undef t2

static unsigned int __threefish1024_encrypt(struct blkcipher_desc *desc,
				  struct blkcipher_walk *walk)
{
	struct threefish_key *ctx = (struct threefish_key *)crypto_blkcipher_ctx(desc->tfm);
	unsigned int bsize = 128;
	unsigned int nbytes = walk->nbytes;
	u64 *src = (u64 *)walk->src.virt.addr;
	u64 *dst = (u64 *)walk->dst.virt.addr;
	u64 tweak = be64_to_cpu(*(u64 *)walk->iv);
	
	while (nbytes >= bsize) {
		threefish_encrypt_1024(ctx, src, dst, tweak++);
		src += 16;
		dst += 16;
		nbytes -= bsize;
	}

	*(u64 *)walk->iv=cpu_to_be64(tweak);
	return nbytes;
}

static int cra_threefish1024_encrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
		     struct scatterlist *src, unsigned int nbytes)
{
	struct blkcipher_walk walk;
	int err;
		
	blkcipher_walk_init(&walk, dst, src, nbytes);
	err = blkcipher_walk_virt(desc, &walk);
		
	while ((nbytes = walk.nbytes)) {
		nbytes = __threefish1024_encrypt(desc, &walk);
		err = blkcipher_walk_done(desc, &walk, nbytes);
	}

	return err;	
}

static unsigned int __threefish1024_decrypt(struct blkcipher_desc *desc,
				  struct blkcipher_walk *walk)
{
	struct threefish_key *ctx = (struct threefish_key *)crypto_blkcipher_ctx(desc->tfm);
	unsigned int bsize = 128;
	unsigned int nbytes = walk->nbytes;
	u64 *src = (u64 *)walk->src.virt.addr;
	u64 *dst = (u64 *)walk->dst.virt.addr;
	u64 tweak = be64_to_cpu(*(u64 *)walk->iv);
	
	while (nbytes >= bsize) {
		threefish_decrypt_1024(ctx, src, dst, tweak++);
		src += 16;
		dst += 16;
		nbytes -= bsize;
	}

	*(u64 *)walk->iv=cpu_to_be64(tweak);
	return nbytes;
}

static int cra_threefish1024_decrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
		     struct scatterlist *src, unsigned int nbytes)
{
	struct blkcipher_walk walk;
	int err;
		
	blkcipher_walk_init(&walk, dst, src, nbytes);
	err = blkcipher_walk_virt(desc, &walk);
		
	while ((nbytes = walk.nbytes)) {
		nbytes = __threefish1024_decrypt(desc, &walk);
		err = blkcipher_walk_done(desc, &walk, nbytes);
	}

	return err;	
}

/* Encrypt one block.  in and out may be the same. */
static void cia_threefish1024_encrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	threefish_encrypt_1024((const struct threefish_key*)crypto_tfm_ctx(tfm), (const u64*)in, (u64*)out, 0);
}

/* Decrypt one block.  in and out may be the same. */
static void cia_threefish1024_decrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	threefish_decrypt_1024((const struct threefish_key*)crypto_tfm_ctx(tfm), (const u64*)in, (u64*)out, 0);
}


static int cia_threefish1024_setkey(struct crypto_tfm *tfm, const u8 *key, unsigned int key_len)
{
	u32 *flags = &tfm->crt_flags;
	
	if (key_len != 128) {
		*flags |= CRYPTO_TFM_RES_BAD_KEY_LEN;
		return -EINVAL;
	}

	threefishSetKey1024((struct threefish_key*)crypto_tfm_ctx(tfm),(u64*)key);
	return 0;
}

static struct crypto_alg threefish_algs[] = { {
.cra_name		= "tweak(threefish)",
	.cra_driver_name	= "threefish1024-generic",
	.cra_priority		= 200,
	.cra_flags		= CRYPTO_ALG_TYPE_BLKCIPHER,
	.cra_blocksize		= 128,
	.cra_ctxsize		= sizeof(struct threefish_key),
	.cra_alignmask		= 0,
	.cra_type		= &crypto_blkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_u = { 
		.blkcipher = {
			.min_keysize	= 128,
			.max_keysize	= 128,
			.ivsize		= 8,
			.setkey		= cia_threefish1024_setkey,
			.encrypt	= cra_threefish1024_encrypt,
			.decrypt	= cra_threefish1024_decrypt,
		}
	}
}, {
	.cra_name           =   "threefish",
	.cra_driver_name    =   "threefish1024-generic",
	.cra_priority       =   100,
	.cra_flags          =   CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize      =   128,
	.cra_ctxsize        =   sizeof(struct threefish_key),
	.cra_alignmask      =	0,
	.cra_module         =   THIS_MODULE,
	.cra_u              =   { 
		.cipher = {
			.cia_min_keysize    =   128,
			.cia_max_keysize    =   128,
			.cia_setkey         =   cia_threefish1024_setkey,
			.cia_encrypt        =   cia_threefish1024_encrypt,
			.cia_decrypt        =   cia_threefish1024_decrypt 
			}
	}
} };


static int __init threefish_mod_init(void)
{
	return crypto_register_algs(threefish_algs, ARRAY_SIZE(threefish_algs));
}

static void __exit threefish_mod_fini(void)
{
	crypto_unregister_algs(threefish_algs, ARRAY_SIZE(threefish_algs));
}

module_init(threefish_mod_init);
module_exit(threefish_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION ("Threefish1024 Cipher Algorithm");
MODULE_ALIAS_CRYPTO("Threefish1024");
MODULE_ALIAS_CRYPTO("threefish1024-generic");
