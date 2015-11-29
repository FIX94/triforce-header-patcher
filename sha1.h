/*
 * This file can be used to work with the SHA1 GnuPG
 * implementation without having any other includes
 */

#ifndef _SHA1_H_
#define _SHA1_H_

typedef struct {
    unsigned int  h0,h1,h2,h3,h4;
    unsigned int  nblocks;
    unsigned char buf[64];
    int  count;
} SHA1_CONTEXT;

void sha1_init( SHA1_CONTEXT *hd );
void sha1_write( SHA1_CONTEXT *hd, unsigned char *inbuf, size_t inlen );
void sha1_final( SHA1_CONTEXT *hd );

#endif
