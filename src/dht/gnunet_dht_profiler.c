/*
     This file is part of GNUnet.
     (C) 2014 Christian Grothoff (and other contributing authors)

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
 * @file dht/gnunet_dht_profiler.c
 * @brief Profiler for GNUnet DHT
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "gnunet_dht_service.h"

#define INFO(...)                                       \
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, __VA_ARGS__)

#define DEBUG(...)                                           \
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__)

/**
 * Number of peers which should perform a PUT out of 100 peers
 */
#define PUT_PROBABILITY 50

/**
 * Configuration
 */
static struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Name of the file with the hosts to run the test over
 */
static char *hosts_file;

/**
 * Context for a peer which actively does DHT PUT/GET
 */
struct ActiveContext;

/**
 * Context to hold data of peer
 */
struct Context
{

  /**
   * The testbed peer this context belongs to
   */
  struct GNUNET_TESTBED_Peer *peer;

  /**
   * Testbed operation acting on this peer
   */
  struct GNUNET_TESTBED_Operation *op;

  /**
   * Active context; NULL if this peer is not an active peer
   */
  struct ActiveContext *ac;
};


/**
 * Context for a peer which actively does DHT PUT/GET
 */
struct ActiveContext
{
  /**
   * The linked peer context
   */
  struct Context *ctx;

  /**
   * Handler to the DHT service
   */
  struct GNUNET_DHT_Handle *dht;

  /**
   * The data used for do a PUT.  Will be NULL if a PUT hasn't been performed yet
   */
  void *put_data;

  /**
   * The active context used for our DHT GET
   */
  struct ActiveContext *get_ac;

  /**
   * The put handle
   */
  struct GNUNET_DHT_PutHandle *dht_put;

  /**
   * The get handle
   */
  struct GNUNET_DHT_GetHandle *dht_get;

  /**
   * The hash of the @e put_data
   */
  struct GNUNET_HashCode hash;

  /**
   * Delay task
   */
  GNUNET_SCHEDULER_TaskIdentifier delay_task;

  /**
   * The size of the @e put_data
   */
  uint16_t put_data_size;

  /**
   * The number of peers currently doing GET on our data
   */
  uint16_t nrefs;
};


/**
 * An array of contexts.  The size of this array should be equal to @a num_peers
 */
static struct Context *a_ctx;

/**
 * Array of active peers
 */
static struct ActiveContext *a_ac;

/**
 * The delay between starting to do PUTS and GETS
 */
static struct GNUNET_TIME_Relative delay;

/**
 * The timeout for GET and PUT
 */
static struct GNUNET_TIME_Relative timeout;

/**
 * Number of peers
 */
static unsigned int num_peers;

/**
 * Number of active peers
 */
static unsigned int n_active;

/**
 * Number of DHT service connections we currently have
 */
static unsigned int n_dht;

/**
 * Number of DHT PUTs made
 */
static unsigned int n_puts;

/**
 * Number of DHT PUTs succeeded
 */
static unsigned int n_puts_ok;

/**
 * Number of DHT PUTs failed
 */
static unsigned int n_puts_fail;

/**
 * Number of DHT GETs made
 */
static unsigned int n_gets;

/**
 * Number of DHT GETs succeeded
 */
static unsigned int n_gets_ok;

/**
 * Number of DHT GETs succeeded
 */
static unsigned int n_gets_fail;

/**
 * Replication degree
 */
static unsigned int replication;


/**
 * Shutdown task.  Cleanup all resources and operations.
 *
 * @param cls NULL
 * @param tc scheduler task context
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ActiveContext *ac;
  unsigned int cnt;

  if (NULL != a_ctx)
  {
    for (cnt=0; cnt < num_peers; cnt++)
    {
      if (NULL != a_ctx[cnt].op)
        GNUNET_TESTBED_operation_done (a_ctx[cnt].op);

      /* Cleanup active context if this peer is an active peer */
      ac = a_ctx[cnt].ac;
      if (NULL == ac)
        continue;
      if (GNUNET_SCHEDULER_NO_TASK != ac->delay_task)
        GNUNET_SCHEDULER_cancel (ac->delay_task);
      if (NULL != ac->put_data)
        GNUNET_free (ac->put_data);
      if (NULL != ac->dht_put)
        GNUNET_DHT_put_cancel (ac->dht_put);
      if (NULL != ac->dht_get)
        GNUNET_DHT_get_stop (ac->dht_get);
    }
    GNUNET_free (a_ctx);
    a_ctx = NULL;
  }
  GNUNET_free_non_null (a_ac);
}


static void
summarize ()
{
  INFO ("# PUTS made: %u\n", n_puts);
  INFO ("# PUTS succeeded: %u\n", n_puts_ok);
  INFO ("# PUTS failed: %u\n", n_puts_fail);
  INFO ("# GETS made: %u\n", n_gets);
  INFO ("# GETS succeeded: %u\n", n_gets_ok);
  INFO ("# GETS failed: %u\n", n_gets_fail);
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Task to cancel DHT GET.
 *
 * @param cls NULL
 * @param tc scheduler task context
 */
static void
cancel_get (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ActiveContext *ac = cls;
  struct Context *ctx = ac->ctx;

  ac->delay_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_assert (NULL != ac->dht_get);
  GNUNET_DHT_get_stop (ac->dht_get);
  ac->dht_get = NULL;
  GNUNET_TESTBED_operation_done (ctx->op);
  ctx->op = NULL;
  n_gets_fail++;

  /* If profiling is complete, summarize */
  if (n_active == n_gets_fail + n_gets_ok)
    summarize ();
}


/**
 * Iterator called on each result obtained for a DHT
 * operation that expects a reply
 *
 * @param cls closure
 * @param exp when will this value expire
 * @param key key of the result
 * @param get_path peers on reply path (or NULL if not recorded)
 *                 [0] = datastore's first neighbor, [length - 1] = local peer
 * @param get_path_length number of entries in @a get_path
 * @param put_path peers on the PUT path (or NULL if not recorded)
 *                 [0] = origin, [length - 1] = datastore
 * @param put_path_length number of entries in @a put_path
 * @param type type of the result
 * @param size number of bytes in @a data
 * @param data pointer to the result data
 */
static void
get_iter (void *cls,
          struct GNUNET_TIME_Absolute exp,
          const struct GNUNET_HashCode *key,
          const struct GNUNET_PeerIdentity *get_path,
          unsigned int get_path_length,
          const struct GNUNET_PeerIdentity *put_path,
          unsigned int put_path_length,
          enum GNUNET_BLOCK_Type type,
          size_t size, const void *data)
{
  struct ActiveContext *ac = cls;
  struct ActiveContext *get_ac = ac->get_ac;
  struct Context *ctx = ac->ctx;

  /* Check the keys of put and get match or not. */
  GNUNET_assert (0 == memcmp (key, &get_ac->hash, sizeof (struct GNUNET_HashCode)));
  /* we found the data we are looking for */
  DEBUG ("We found a GET request; %u remaining\n", n_gets - (n_gets_fail + n_gets_ok));
  n_gets_ok++;
  get_ac->nrefs--;
  GNUNET_DHT_get_stop (ac->dht_get);
  ac->dht_get = NULL;
  GNUNET_SCHEDULER_cancel (ac->delay_task);
  ac->delay_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_TESTBED_operation_done (ctx->op);
  ctx->op = NULL;
  
  /* Summarize if profiling is complete */
  if (n_active == n_gets_fail + n_gets_ok)
    summarize ();
}


/**
 * Task to do DHT GETs
 *
 * @param cls the active context
 * @param tc the scheduler task context
 */
static void
delayed_get (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ActiveContext *ac = cls;
  struct ActiveContext *get_ac;
  unsigned int r;

  ac->delay_task = GNUNET_SCHEDULER_NO_TASK;
  get_ac = NULL;
  while (1)
  {
    r = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, n_active);
    get_ac = &a_ac[r];
    if (NULL != get_ac->put_data)
      break;
  }
  get_ac->nrefs++;
  ac->get_ac = get_ac;
  DEBUG ("Doing a DHT GET for data of size %u\n", get_ac->put_data_size);
  ac->dht_get = GNUNET_DHT_get_start (ac->dht,
                                      GNUNET_BLOCK_TYPE_TEST,
                                      &get_ac->hash,
                                      1, /* replication level */
                                      GNUNET_DHT_RO_NONE,
                                      NULL, 0, /* extended query and size */
                                      get_iter, ac); /* GET iterator and closure
                                                        */
  n_gets++;

  /* schedule the timeout task for GET */
  ac->delay_task = GNUNET_SCHEDULER_add_delayed (timeout, &cancel_get, ac);
}


/**
 * Queue up a delayed task for doing DHT GET
 *
 * @param cls the active context
 * @param success #GNUNET_OK if the PUT was transmitted,
 *                #GNUNET_NO on timeout,
 *                #GNUNET_SYSERR on disconnect from service
 *                after the PUT message was transmitted
 *                (so we don't know if it was received or not)
 */
static void
put_cont (void *cls, int success)
{
  struct ActiveContext *ac = cls;

  ac->dht_put = NULL;
  if (success)
    n_puts_ok++;
  else
    n_puts_fail++;
  ac->delay_task = GNUNET_SCHEDULER_add_delayed (delay, &delayed_get, ac);
}


/**
 * Task to do DHT PUTS
 *
 * @param cls the active context
 * @param tc the scheduler task context
 */
static void
delayed_put (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ActiveContext *ac = cls;

  ac->delay_task = GNUNET_SCHEDULER_NO_TASK;
  /* Generate and DHT PUT some random data */
  ac->put_data_size = 16;       /* minimum */
  ac->put_data_size += GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                                 (63*1024));
  ac->put_data = GNUNET_malloc (ac->put_data_size);
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK,
                              ac->put_data, ac->put_data_size);
  GNUNET_CRYPTO_hash (ac->put_data, ac->put_data_size, &ac->hash);
  DEBUG ("Doing a DHT PUT with data of size %u\n", ac->put_data_size);
  ac->dht_put = GNUNET_DHT_put (ac->dht, &ac->hash,
                                replication,
                                GNUNET_DHT_RO_NONE,
                                GNUNET_BLOCK_TYPE_TEST,
                                ac->put_data_size,
                                ac->put_data,
                                GNUNET_TIME_UNIT_FOREVER_ABS, /* expiration time */
                                timeout,                      /* PUT timeout */
                                put_cont, ac);                /* continuation and its closure */
  n_puts++;
}


/**
 * Connection to DHT has been established.  Call the delay task.
 *
 * @param cls the active context
 * @param op the operation that has been finished
 * @param ca_result the service handle returned from GNUNET_TESTBED_ConnectAdapter()
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void
dht_connected (void *cls,
               struct GNUNET_TESTBED_Operation *op,
               void *ca_result,
               const char *emsg)
{
  struct ActiveContext *ac = cls;
  struct Context *ctx = ac->ctx;

  GNUNET_assert (NULL != ctx);
  GNUNET_assert (NULL != ctx->op);
  GNUNET_assert (ctx->op == op);
  ac->dht = (struct GNUNET_DHT_Handle *) ca_result;
  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Connection to DHT service failed: %s\n", emsg);
    GNUNET_TESTBED_operation_done (ctx->op); /* Calls dht_disconnect() */
    ctx->op = NULL;
    return;
  }
  ac->delay_task = GNUNET_SCHEDULER_add_delayed (delay, &delayed_put, ac);
}


/**
 * Connect to DHT service and return the DHT client handler
 *
 * @param cls the active context
 * @param cfg configuration of the peer to connect to; will be available until
 *          GNUNET_TESTBED_operation_done() is called on the operation returned
 *          from GNUNET_TESTBED_service_connect()
 * @return service handle to return in 'op_result', NULL on error
 */
static void *
dht_connect (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  n_dht++;
  return GNUNET_DHT_connect (cfg, 10);
}


/**
 * Adapter function called to destroy a connection to
 * a service.
 *
 * @param cls the active context
 * @param op_result service handle returned from the connect adapter
 */
static void
dht_disconnect (void *cls, void *op_result)
{
  struct ActiveContext *ac = cls;

  GNUNET_assert (NULL != ac->dht);
  GNUNET_assert (ac->dht == op_result);
  GNUNET_DHT_disconnect (ac->dht);
  n_dht--;
  if (0 == n_dht)
    GNUNET_SCHEDULER_shutdown ();
}


/**
 * Callback called when DHT service on the peer is started
 *
 * @param cls the context
 * @param op the operation that has been finished
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void
service_started (void *cls,
                 struct GNUNET_TESTBED_Operation *op,
                 const char *emsg)
{
  struct Context *ctx = cls;

  GNUNET_assert (NULL != ctx);
  GNUNET_assert (NULL != ctx->op);
  GNUNET_TESTBED_operation_done (ctx->op);
  ctx->op = NULL;
  if (NULL == ctx->ac)
    return;
  /* FIXME: connect to the DHT service and wait before starting a PUT */
  ctx->op = GNUNET_TESTBED_service_connect (ctx, ctx->peer,
                                            "dht",
                                            &dht_connected, ctx->ac,
                                            &dht_connect,
                                            &dht_disconnect,
                                            ctx->ac);
}


/**
 * Signature of a main function for a testcase.
 *
 * @param cls closure
 * @param h the run handle
 * @param num_peers number of peers in 'peers'
 * @param peers handle to peers run in the testbed
 * @param links_succeeded the number of overlay link connection attempts that
 *          succeeded
 * @param links_failed the number of overlay link
 */
static void
test_run (void *cls,
          struct GNUNET_TESTBED_RunHandle *h,
          unsigned int num_peers, struct GNUNET_TESTBED_Peer **peers,
          unsigned int links_succeeded,
          unsigned int links_failed)
{
  unsigned int cnt;
  unsigned int ac_cnt;
    
  if (NULL == peers)
  {
    /* exit */
    GNUNET_assert (0);
  }
  INFO ("%u peers started\n", num_peers);
  a_ctx = GNUNET_malloc (sizeof (struct Context) * num_peers);

  /* select the peers which actively participate in profiling */
  n_active = num_peers * PUT_PROBABILITY / 100;
  if (0 == n_active)
  {
    GNUNET_SCHEDULER_shutdown ();
    GNUNET_free (a_ctx);
    return;
  }
  a_ac = GNUNET_malloc (n_active * sizeof (struct ActiveContext));
  ac_cnt = 0;
  for (cnt = 0; cnt < num_peers && ac_cnt < n_active; cnt++)
  {
    if (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 100) >=
        PUT_PROBABILITY)
      continue;
    a_ctx[cnt].ac = &a_ac[ac_cnt];
    a_ac[ac_cnt].ctx = &a_ctx[cnt];
    ac_cnt++;
  }
  n_active = ac_cnt;
  a_ac = GNUNET_realloc (a_ac, n_active * sizeof (struct ActiveContext));
  INFO ("Active peers: %u\n", n_active);

  /* start DHT service on all peers */
  for (cnt = 0; cnt < num_peers; cnt++)
  {
    a_ctx[cnt].peer = peers[cnt];
    a_ctx[cnt].op = GNUNET_TESTBED_peer_manage_service (&a_ctx[cnt],
                                                        peers[cnt],
                                                        "dht",
                                                        &service_started,
                                                        &a_ctx[cnt],
                                                        1);
  }
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param config configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *config)
{
  uint64_t event_mask;

  if (0 == num_peers)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Exiting as the number of peers is %u\n"),
                num_peers);
    return;
  }
  cfg = GNUNET_CONFIGURATION_dup (config);
  event_mask = 0;
  GNUNET_TESTBED_run (hosts_file, cfg, num_peers, event_mask, NULL,
                      NULL, &test_run, NULL);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &do_shutdown,
                                NULL);
}


/**
 * Main function.
 *
 * @return 0 on success
 */
int
main (int argc, char *const *argv)
{
  int rc;

  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'n', "peers", "COUNT",
     gettext_noop ("number of peers to start"),
     1, &GNUNET_GETOPT_set_uint, &num_peers},
    {'H', "hosts", "FILENAME",
     gettext_noop ("name of the file with the login information for the testbed"),
     1, &GNUNET_GETOPT_set_string, &hosts_file},
    {'d', "delay", "DELAY",
     gettext_noop ("delay for starting DHT PUT and GET"),
     1, &GNUNET_GETOPT_set_relative_time, &delay},
    {'r', "replication", "DEGREE",
     gettext_noop ("replication degree for DHT PUTs"),
     1, &GNUNET_GETOPT_set_uint, &replication},
    {'t', "timeout", "TIMEOUT",
     gettext_noop ("timeout for DHT PUT and GET requests"),
     1, &GNUNET_GETOPT_set_relative_time, &timeout},
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;
  delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 3); /* default delay */
  timeout = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 3); /* default timeout */
  replication = 1;      /* default replication */
  rc = 0;
  if (GNUNET_OK !=
      GNUNET_PROGRAM_run (argc, argv, "dht-profiler",
			  gettext_noop
			  ("Measure quality and performance of the DHT service."),
			  options, &run, NULL))
    rc = 1;
  return rc;
}
