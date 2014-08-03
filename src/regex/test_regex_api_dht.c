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
#define TOTAL_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)

/**
 * How long until we give up on any particular operation (and retry)?
 */
#define BASE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 3)


/**
 * The result the test can have.
 */
enum test_result_e {
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


/**
 * The signature of a test case so that it can be added to the main loop that
 * runs all test cases
 */
typedef enum test_result_e (*Test_Case)(void);


static struct GNUNET_REGEX_Announcement *a;

static struct GNUNET_REGEX_Search *s;

static enum test_result_e test_case_result = FAIL;


static void
peer_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != a)
  {
    GNUNET_REGEX_announce_cancel (a);
  }
  if (NULL != s)
  {
    GNUNET_REGEX_search_cancel (s);
  }

  s = NULL;
  a = NULL;
}


static enum test_result_e
launch_test_peer (GNUNET_TESTING_TestMain tm, void *cls)
{
  if (0 != GNUNET_TESTING_peer_run ("test-regex-api",
            "test_regex_api_data.conf",
            tm, cls))
    return FAIL;
  if (SUCCESS != test_case_result)
  {
    return FAIL;
  }

  return SUCCESS;
}


static void
announce_get_dht_accept_states_cb (void *cls,
    struct GNUNET_REGEX_Announcement *passed_a,
    struct GNUNET_CONTAINER_MultiHashMap *accepting_states)
{
  if (a == passed_a)
  {
    if (NULL != accepting_states)
    {
      if (0 < GNUNET_CONTAINER_multihashmap_size(accepting_states))
      {
        // TODO: Look up the DHT if there is really a REGEX block there
        test_case_result = SUCCESS;
      }
      else
      {
        GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, "regex", "empty hashmap\n");
      }
    }
    else
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, "regex", "NULL hashmap\n");
    }
  }

  GNUNET_SCHEDULER_shutdown ();
}


static void
announce_get_dht_accept_states_peer_run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  GNUNET_SCHEDULER_add_delayed (TOTAL_TIMEOUT, &peer_shutdown, NULL);

  char *announce_message = "dht_test(1|2)";

  a = GNUNET_REGEX_announce (cfg,
    announce_message,
    GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5),
    1);

  // TODO: Check the return of the call
  GNUNET_REGEX_announce_get_accepting_dht_entries(a,
      &announce_get_dht_accept_states_cb,
      announce_message);
}


static enum test_result_e
test_announce_get_dht_accept_states (void)
{
  return launch_test_peer (&announce_get_dht_accept_states_peer_run, NULL);
}


int
main (int argc, char *argv[])
{
  Test_Case tests[] = { test_announce_get_dht_accept_states };

  unsigned int num_tests = sizeof (tests) / sizeof (Test_Case);
  unsigned int i;
  for (i = 0; i < num_tests; i++)
  {
    test_case_result = FAIL;
    if (SUCCESS != tests[i] ())
    {
      return 1;
    }
  }

  return 0;
}

/* end of test_regex_api.c */
