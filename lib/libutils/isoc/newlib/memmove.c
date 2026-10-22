// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 1994-2009  Red Hat, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
FUNCTION
	<<memmove>>---move possibly overlapping memory

INDEX
	memmove

ANSI_SYNOPSIS
	#include <string.h>
	void *memmove(void *<[dst]>, const void *<[src]>, size_t <[length]>);

TRAD_SYNOPSIS
	#include <string.h>
	void *memmove(<[dst]>, <[src]>, <[length]>)
	void *<[dst]>;
	void *<[src]>;
	size_t <[length]>;

DESCRIPTION
	This function moves <[length]> characters from the block of
	memory starting at <<*<[src]>>> to the memory starting at
	<<*<[dst]>>>. <<memmove>> reproduces the characters correctly
	at <<*<[dst]>>> even if the two areas overlap.

RETURNS
	The function returns <[dst]> as passed.

PORTABILITY
<<memmove>> is ANSI C.

<<memmove>> requires no supporting OS subroutines.

QUICKREF
	memmove ansi pure
*/

#include <string.h>
#include "_ansi.h"
#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#if !defined(PREFER_SIZE_OVER_SPEED) && !defined(__OPTIMIZE_SIZE__) && \
	defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
/*
 * Word copy for any alignment, also for overlapping buffers. The destination is
 * aligned first. Then each destination word is copied from an aligned source
 * word, or merged from two aligned source words with shifts if the source is
 * misaligned. All the word accesses are aligned, so this works with
 * -mstrict-align. An aligned source word may contain bytes outside of the
 * source buffer, but never crosses a page boundary.
 */
#define USE_WORD_COPY

typedef unsigned long __attribute__((__may_alias__)) word_t;

#define WSIZE	sizeof(word_t)
#define WMASK	(WSIZE - 1)

/* Threshhold for punting to the byte copier.  */
#define TOO_SMALL(LEN)	((LEN) < (WSIZE << 2))

/* Copies |nw| words to the aligned |d| from the aligned |s|. */
static void copy_words_fwd(word_t *d, const word_t *s, size_t nw)
{
	/*
	 * Unroll 4x manually because -O2 does not unroll loops with a runtime
	 * trip count, reducing loop overhead from 5 to 3 instructions/word.
	 */
	for (; nw >= 4; nw -= 4) {
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
	}

	/* Copy one word at a time if possible. */
	while (nw--)
		*d++ = *s++;
}

/*
 * Copies |nw| (>= 1) words to the aligned |d| from the misaligned |s| in
 * increasing addresses, merging two aligned source words into each destination
 * word.
 *
 • (uintptr_t)s & WMASK is the byte offset k of s past its nearest aligned word
 * boundary.
 • ls = k * 8 is the number of bits to discard from the lower address word (lo).
 • rs = (WSIZE - k) * 8 is the bit position where the upper word's bytes (hi)
 *     must be placed.
 *
 * Concrete example (32-bit little-endian, WSIZE = 4, s = 0x1001):
 *
 *   Address:  0x1000  0x1001  0x1002  0x1003 | 0x1004  0x1005  0x1006  0x1007
 *   Bytes:    [ XX ]  [ B0 ]  [ B1 ]  [ B2 ] | [ B3 ]  [ B4 ]  [ B5 ]  [ B6 ]
 *               ^       ^                        ^
 *               |       +-- s = 0x1001           +-- sw[1] = 0x1004
 *               +---------- sw[0] = 0x1000 (s & ~3)
 *
 *   1. Shift widths:
 *        ls = (0x1001 & 3) * 8 = 8 bits
 *        rs = 32 - 8 = 24 bits
 *   2. Aligned loads (little-endian register order MSB..LSB):
 *        lo = sw[0] = 0xB2_B1_B0_XX
 *        hi = sw[1] = 0xB6_B5_B4_B3
 *   3. Shift and merge:
 *        lo >> 8  : 0x00_B2_B1_B0  (shifts out XX; B0..B2 move to byte 0..2)
 *        hi << 24 : 0xB3_00_00_00  (shifts out B4..B6; B3 moves to byte 3)
 *        ------------------------ OR (|)
 *        *d++     : 0xB3_B2_B1_B0  (stored to aligned d as [B0, B1, B2, B3])
 */
static void merge_words_fwd(word_t *d, const unsigned char *s, size_t nw)
{
	const unsigned int ls = ((uintptr_t)s & WMASK) * CHAR_BIT;
	const unsigned int rs = WSIZE * CHAR_BIT - ls;
	const word_t *sw = (const word_t *)((uintptr_t)s & ~WMASK);
	word_t lo = *sw++;

	while (nw--) {
		word_t hi = *sw++;

		*d++ = (lo >> ls) | (hi << rs);
		lo = hi;
	}
}

/*
 * Copies |nw| words that end at the aligned |d| from the words that end at the
 * aligned |s| in decreasing addresses.
 */
static void copy_words_bwd(word_t *d, const word_t *s, size_t nw)
{
	while (nw--)
		*--d = *--s;
}

/*
 * Copies |nw| (>= 1) words that end at the aligned |d| from the bytes that end
 * at the misaligned |s| in decreasing addresses, merging two aligned source
 * words into each destination word. See the comments in merge_words_fwd().
 */
static void merge_words_bwd(word_t *d, const unsigned char *s, size_t nw)
{
	const unsigned int ls = ((uintptr_t)s & WMASK) * CHAR_BIT;
	const unsigned int rs = WSIZE * CHAR_BIT - ls;
	const word_t *sw = (const word_t *)((uintptr_t)s & ~WMASK);
	word_t hi = *sw;

	while (nw--) {
		word_t lo = *--sw;

		*--d = (lo >> ls) | (hi << rs);
		hi = lo;
	}
}
#endif

/* SUPPRESS 20 */
_PTR
_DEFUN(memmove, (dst_void, src_void, length), _PTR dst_void _AND _CONST _PTR
	src_void _AND size_t length)
{
	char *dst = dst_void;
	_CONST char *src = src_void;

	if (src < dst && dst < src + length) {
		/* Destructive overlap...have to copy backwards */
		src += length;
		dst += length;
#ifdef USE_WORD_COPY
		if (!TOO_SMALL(length)) {
			size_t nw;

			/* Copy bytes until the end of DST is aligned. */
			while ((uintptr_t)dst & WMASK) {
				*--dst = *--src;
				length--;
			}
			nw = length / WSIZE;
			if ((uintptr_t)src & WMASK)
				merge_words_bwd((word_t *)dst,
						(_CONST unsigned char *)src, nw);
			else
				copy_words_bwd((word_t *)dst,
					       (_CONST word_t *)src, nw);
			dst -= nw * WSIZE;
			src -= nw * WSIZE;
			length -= nw * WSIZE;
		}
#endif
		while (length--)
			*--dst = *--src;
	} else {
#ifdef USE_WORD_COPY
		/*
		 * Use optimizing algorithm for a non-destructive copy to
		 * closely match memcpy. If the size is small, then punt into
		 * the byte copy loop.
		 */
		if (!TOO_SMALL(length)) {
			size_t nw;

			/* Copy bytes until DST is aligned. */
			while ((uintptr_t)dst & WMASK) {
				*dst++ = *src++;
				length--;
			}
			nw = length / WSIZE;
			if ((uintptr_t)src & WMASK)
				merge_words_fwd((word_t *)dst,
						(_CONST unsigned char *)src, nw);
			else
				copy_words_fwd((word_t *)dst,
					       (_CONST word_t *)src, nw);
			dst += nw * WSIZE;
			src += nw * WSIZE;
			length -= nw * WSIZE;
		}
#endif
		while (length--)
			*dst++ = *src++;
	}

	return dst_void;
}
