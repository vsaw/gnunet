/*
     This file is part of GNUnet.
     (C) 2013 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
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
 * @file regex/test_regex_api.c
 * @brief base test case for regex api (and DHT functions)
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_regex_service.h"


/**
 * How long until we really give up on a particular testcase portion?
 */
#define TOTAL_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 600)

/**
 * How long until we give up on any particular operation (and retry)?
 */
#define BASE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 3)


/**
 * The result the test can have.
 */
enum test_result_e {
  UNKNOWN,
  FAIL,
  SUCCESS
};


/**
 * Closure to be passed to the found callback to tell him the keys and config
 */
struct key_config_cls {
  /**
   * The config used for runnig this test.
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * The private EdDSA key used for the announcement
   */
  struct GNUNET_CRYPTO_EddsaPrivateKey *eddsa_key;
};


static struct GNUNET_REGEX_Announcement *a;

static struct GNUNET_REGEX_Search *s;

static enum test_result_e test_result = UNKNOWN;


static void
end (void *cls,
     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_REGEX_announce_cancel (a);
  a = NULL;
  GNUNET_REGEX_search_cancel (s);
  s = NULL;
}


/**
 * Search callback function, invoked for every result that was found.
 *
 * @param cls Closure provided in GNUNET_REGEX_search.
 * @param id Peer providing a regex that matches the string.
 * @param get_path Path of the get request.
 * @param get_path_length Lenght of get_path.
 * @param put_path Path of the put request.
 * @param put_path_length Length of the put_path.
 */
static void
found_cb (void *cls,
	  const struct GNUNET_PeerIdentity *id,
	  const struct GNUNET_PeerIdentity *get_path,
	  unsigned int get_path_length,
	  const struct GNUNET_PeerIdentity *put_path,
	  unsigned int put_path_length,
	  const struct GNUNET_HashCode *key)
{
  struct key_config_cls *cfg_cls;
  struct GNUNET_CRYPTO_EddsaPrivateKey *expected_priv_key;
  struct GNUNET_CRYPTO_EddsaPublicKey pub_key;

  cfg_cls = (struct key_config_cls *) cls;

  // Determine the expected private key from the closure. If it does not
  // contain one skip the check if the signature is generated from the correct
  // private key
  expected_priv_key = cfg_cls->eddsa_key;
  if (NULL != expected_priv_key)
  {
    // Now generate the public key and match it against id
    GNUNET_CRYPTO_eddsa_key_get_public(expected_priv_key, &pub_key);

    if (memcmp (&pub_key, &(id->public_key), sizeof (struct GNUNET_CRYPTO_EddsaPublicKey)))
    {
      test_result = FAIL;
    }
  }

  // At last check if the dht_key is not NULL but only do this if the public
  // key check did not fail. Otherwise it would overwrite the test result
  if (UNKNOWN == test_result && NULL != key)
  {
    test_result = SUCCESS;
  }

  GNUNET_SCHEDULER_shutdown ();
}


static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  static struct key_config_cls found_cb_cls;
  found_cb_cls.cfg = cfg;
  found_cb_cls.eddsa_key = (struct GNUNET_CRYPTO_EddsaPrivateKey *) cls;

  GNUNET_SCHEDULER_add_delayed (TOTAL_TIMEOUT, &end, NULL);

  if (NULL == cls)
  {
    a = GNUNET_REGEX_announce (cfg,
			     "my long prefix - hello world(0|1)*",
			     GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5),
			     1);
  }
  else
  {
    a = GNUNET_REGEX_announce_with_key (cfg,
               "my long prefix - hello world(0|1)*",
               GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5),
               1,
               found_cb_cls.eddsa_key);
  }


  s = GNUNET_REGEX_search (cfg,
			   "my long prefix - hello world0101",
			   &found_cb, &found_cb_cls);
}


int
main (int argc, char *argv[])
{
  if (0 != GNUNET_TESTING_peer_run ("test-regex-api",
				    "test_regex_api_data.conf",
				    &run, NULL))
    return 1;
  if (SUCCESS != test_result)
  {
    return 1;
  }

  if (0 != GNUNET_TESTING_peer_run ("test-regex-api",
                                    "test_regex_api_data.conf",
                                    &run,
                                    GNUNET_CRYPTO_eddsa_key_get_anonymous ()))
  {
    return 1;
  }
  if (SUCCESS != test_result)
  {
    return 1;
  }

  return 0;
}

/* end of test_regex_api.c */
