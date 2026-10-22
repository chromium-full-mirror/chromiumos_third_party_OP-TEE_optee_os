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

#if !defined(PREFER_SIZE_OVER_SPEED) && !defined(__OPTIMIZE_SIZE__)
#define USE_WORD_COPY

typedef unsigned long __attribute__((__may_alias__)) word_t;

#define WSIZE	sizeof(word_t)
#define WMASK	(WSIZE - 1)

/* Nonzero if either X or Y is not aligned on a "long" boundary.  */
#define UNALIGNED(X, Y)	(((uintptr_t)(X) | (uintptr_t)(Y)) & WMASK)

/* Threshhold for punting to the byte copier.  */
#define TOO_SMALL(LEN)	((LEN) < (WSIZE << 2))

/* Copies |nw| words to the aligned |d| from the aligned |s|. */
static void copy_words_fwd(word_t *d, const word_t *s, size_t nw)
{
	/* Copy 4X long words at a time if possible.  */
	for (; nw >= 4; nw -= 4) {
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
	}

	/* Copy one long word at a time if possible.  */
	while (nw--)
		*d++ = *s++;
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
		while (length--)
			*--dst = *--src;
	} else {
#ifdef USE_WORD_COPY
		/*
		 * Use optimizing algorithm for a non-destructive copy to
		 * closely match memcpy. If the size is small or either SRC or
		 * DST is unaligned, then punt into the byte copy loop.  This
		 * should be rare.
		 */
		if (!TOO_SMALL(length) && !UNALIGNED(src, dst)) {
			size_t nw = length / WSIZE;

			copy_words_fwd((word_t *)dst, (_CONST word_t *)src, nw);
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
