/*
     This file is part of GNUnet.
     (C) 2002, 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.

*/
/**
 * SymCipher testcode.
 * @author Christian Grothoff
 * @file util/crypto/symciphertest.c
 */

#include "gnunet_util.h"
#include "gnunet_util_crypto.h"
#include "platform.h"

#define TESTSTRING "Hello World!"
#define INITVALUE "InitializationVectorValue"

static int testSymcipher() {
  SESSIONKEY key;
  char result[100];
  int size;
  char res[100];

  makeSessionkey(&key);
  size = encryptBlock(TESTSTRING,
  	      strlen(TESTSTRING)+1,
  	      &key,
  	      (const INITVECTOR*) INITVALUE,
  	      result);
  if (size == -1) {
    printf("symciphertest failed: encryptBlock returned %d\n",
    size);
    return 1;
  }
  size = decryptBlock(&key,
  	      result,
  	      size,
  	      (const INITVECTOR*) INITVALUE,
  	      res);
  if (strlen(TESTSTRING)+1
      != size) {
    printf("symciphertest failed: decryptBlock returned %d\n",
    size);
    return 1;
  }
  if (0 != strcmp(res,TESTSTRING)) {
    printf("symciphertest failed: %s != %s\n",
     res, TESTSTRING);
    return 1;
  } else
    return 0;
}

int verifyCrypto() {
  SESSIONKEY key;
  char result[SESSIONKEY_LEN];
  char * res;
  int ret;

  unsigned char plain[] = {29, 128, 192, 253, 74, 171, 38, 187, 84, 219, 76, 76, 209, 118, 33, 249, 172, 124, 96, 9, 157, 110, 8, 215, 200, 63, 69, 230, 157, 104, 247, 164};
  unsigned char raw_key[] = {106, 74, 209, 88, 145, 55, 189, 135, 125, 180, 225, 108, 183, 54, 25, 169, 129, 188, 131, 75, 227, 245, 105, 10, 225, 15, 115, 159, 148, 184, 34, 191};
  unsigned char encrresult[] = {167, 102, 230, 233, 127, 195, 176, 107, 17, 91, 199, 127, 96, 113, 75, 195, 245, 217, 61, 236, 159, 165, 103, 121, 203, 99, 202, 41, 23, 222, 25, 102, 1 };

  res = NULL;
  ret = 0;

  memcpy(key.key, raw_key, SESSIONKEY_LEN);
  key.crc32 = htonl(crc32N(&key, SESSIONKEY_LEN));

  if (ntohl(key.crc32) != (unsigned int) 38125195LL) {
    printf("Static key has different CRC: %u - %u\n",
     ntohl(key.crc32),
     key.crc32);

    ret = 1;
    goto error;
  }

  if (SESSIONKEY_LEN !=
      encryptBlock(plain,
  	   SESSIONKEY_LEN,
  	   &key,
  	   (const INITVECTOR*) "testtesttesttest",
  	   result)) {
    printf("Wrong return value from encrypt block.\n");
    ret = 1;
    goto error;
  }

  if (memcmp(encrresult,
       result,
       SESSIONKEY_LEN) != 0) {
    printf("Encrypted result wrong.\n");
    ret = 1;
    goto error;
  }

  res = MALLOC(SESSIONKEY_LEN);

  if (SESSIONKEY_LEN !=
      decryptBlock(&key,
  	   result,
  	   SESSIONKEY_LEN,
  	   (const INITVECTOR*) "testtesttesttest",
  	   res)) {
    printf("Wrong return value from decrypt block.\n");
    ret = 1;
    goto error;
  }

  if (memcmp(res, plain, SESSIONKEY_LEN) != 0) {
    printf("Decrypted result does not match input.\n");

    ret = 1;
  }

error:

  FREENONNULL(res);

  return ret;
}

int main(int argc, char * argv[]) {
  int failureCount = 0;

  GE_ASSERT(NULL, strlen(INITVALUE) > sizeof(INITVECTOR));
  failureCount += testSymcipher();
  failureCount += verifyCrypto();

  if (failureCount != 0) {
    printf("%d TESTS FAILED!\n",failureCount);
    return -1;
  }
  return 0;
}

/* end of symciphertest.c */
