#include <unistd.h>
#include <gnunet/platform.h>
#include <gnunet/gnunet_util_lib.h>
#include <gnunet/gnunet_testbed_service.h>
#include <gnunet/gnunet_dht_service.h>
#include <gnunet/gnunet_regex_service.h>


/**
 * LOG using this modules name
 *
 * @param kind One of GNUNET_ERROR_TYPE
 * @param ... The format sting and optional arguments
 */
#define LOG(kind, ...) //GNUNET_log_from (kind, "test-regex-anonymous-api", __VA_ARGS__)
/**
 * Log debug messages for this module
 *
 * @param ... The format sting and optional arguments
 *
 * TODO: change type to GNUNET_ERROR_TYPE_DEBUG if bash config is fixed
 * I set it to warning because debug output is currently not appearing on bash
 * for some reason I don't know.
 */
#define LOG_DEBUG(...) LOG (GNUNET_ERROR_TYPE_WARNING, __VA_ARGS__)
/**
 * Log error messages for this module
 *
 * @param ... The format sting and optional arguments
 */
#define LOG_ERROR(...) LOG (GNUNET_ERROR_TYPE_ERROR, __VA_ARGS__)
/**
 * Log warning messages for this module
 *
 * @param ... The format sting and optional arguments
 */
#define LOG_WARNING(...) LOG (GNUNET_ERROR_TYPE_WARNING, __VA_ARGS__)
/**
 * Number of peers we want to start
 *
 * 1 Publisher, 1 Suscriber so far.
 */
#define NUM_PEERS 2
/**
 * Dunno, this value was taken from the testbed_test example
 */
#define HT_LENGTH_DEFAULT 10


/**
 * Describes how to configure the publisher
 */
struct Publisher_Config {
  /**
   * The topic of the publisher
   */
  char *topic;
  struct GNUNET_TESTBED_Operation *op;
  /**
   * size of the internal hash table to use for processing multiple GET/FIND
   * requests in parallel
   */
  unsigned int ht_length;
  struct GNUNET_DHT_Handle *dht_handle;
  /**
   * The configuration for the publisher peer
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;
  /**
   * The search performed by the publisher to find subscribers
   */
  struct GNUNET_REGEX_Search *regex_search;
  /**
   * The handle for the DHT put operation
   */
  struct GNUNET_DHT_PutHandle *put_handle;
  /**
   * The publishers identity as determined from the configuration
   */
  struct GNUNET_PeerIdentity identity;
};


/**
 * Describes how to configure the subscriber
 */
struct Subscriber_Config {
  /**
   * The topic/subscription of the subscriber
   *
   * Note that the subscriber is right now limited to one subscription only!
   */
  char *topic;
  struct GNUNET_TESTBED_Operation *op;
  /**
   * size of the internal hash table to use for processing multiple GET/FIND
   * requests in parallel
   */
  unsigned int ht_length;
  struct GNUNET_DHT_Handle *dht_handle;
  /**
   * The configuration for the subscriber peer
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;
  /**
   * The subscribers identity as determined from the configuration
   */
  struct GNUNET_PeerIdentity identity;
  /**
   * Handle to the subscription announcement
   */
  struct GNUNET_REGEX_Announcement *regex_announcement;
};


/**
 * The result of the tesbed simulation.
 *
 * Either GNUNET_OK or GNUNET_SYSERR
 */
static int result = GNUNET_SYSERR;
/**
 * The main cls for the publisher.
 */
static struct Publisher_Config publisher_conf;
/**
 * The main cls for the subscriber
 */
static struct Subscriber_Config subscriber_conf;
/**
 * Handle to the shutdown task. Used for scheduling
 */
static GNUNET_SCHEDULER_TaskIdentifier shutdown_tid = GNUNET_SCHEDULER_NO_TASK;


/**
 * Function run on CTRL-C or shutdown (i.e. success/timeout/etc.).
 * Cleans up.
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != subscriber_conf.op)
  {
    GNUNET_TESTBED_operation_done(subscriber_conf.op);
    subscriber_conf.op = NULL;
  }

  // shut down the publisher
  if (NULL != publisher_conf.op)
  {
    GNUNET_TESTBED_operation_done(publisher_conf.op);
    publisher_conf.op = NULL;
  }

  /* Also kills the testbed */
  shutdown_tid = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Schedule a shutdown after certain amount of seconds
 *
 * @param seconds The amount of seconds to wait until the shutdown from the
 *        current point in time
 *
 * Previously scheduled shutdowns will be cancelled and a new time for the
 * shutdown is set.
 */
static void
schedule_shutdown_test (uint16_t seconds)
{
  if (GNUNET_SCHEDULER_NO_TASK != shutdown_tid)
  {
    GNUNET_SCHEDULER_cancel (shutdown_tid);
  }
  shutdown_tid = GNUNET_SCHEDULER_add_delayed (
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, seconds),
      &shutdown_task,
      NULL);
}


/**
 * Callback called on each GET request going through the DHT.
 *
 * @param cls Closure.
 * @param options Options, for instance RecordRoute, DemultiplexEverywhere.
 * @param type The type of data in the request.
 * @param hop_count Hop count so far.
 * @param path_length number of entries in @a path (or 0 if not recorded).
 * @param path peers on the GET path (or NULL if not recorded).
 * @param desired_replication_level Desired replication level.
 * @param key Key of the requested data.
 */
void
subscriber_monitor_get_cb (void *cls,
    enum GNUNET_DHT_RouteOption options,
    enum GNUNET_BLOCK_Type type,
    uint32_t hop_count,
    uint32_t desired_replication_level,
    unsigned int path_length,
    const struct GNUNET_PeerIdentity *path,
    const struct GNUNET_HashCode * key)
{
  LOG_DEBUG("Subscriber monitor get callback called %s\n", GNUNET_h2s(key));
}


/**
 * Callback called on each GET reply going through the DHT.
 *
 * @param cls Closure.
 * @param type The type of data in the result.
 * @param get_path Peers on GET path (or NULL if not recorded).
 * @param get_path_length number of entries in @a get_path.
 * @param put_path peers on the PUT path (or NULL if not recorded).
 * @param put_path_length number of entries in @a get_path.
 * @param exp Expiration time of the data.
 * @param key Key of the data.
 * @param data Pointer to the result data.
 * @param size Number of bytes in @a data.
 */
void
subscriber_monitor_get_response_cb (void *cls,
    enum GNUNET_BLOCK_Type type,
    const struct GNUNET_PeerIdentity *get_path,
    unsigned int get_path_length,
    const struct GNUNET_PeerIdentity *put_path,
    unsigned int put_path_length,
    struct GNUNET_TIME_Absolute exp,
    const struct GNUNET_HashCode *key,
    const void *data,
    size_t size)
{
  LOG_DEBUG("Subscriber monitor get response callback called %s\n",
            GNUNET_h2s(key));
  LOG_DEBUG("Subscriber monitor get response data %s\n",
            GNUNET_i2s((struct GNUNET_PeerIdentity  *) data));
}


/**
 * Callback called on each PUT request going through the DHT.
 *
 * @param cls Closure.
 * @param options Options, for instance RecordRoute, DemultiplexEverywhere.
 * @param type The type of data in the request.
 * @param hop_count Hop count so far.
 * @param path_length number of entries in @a path (or 0 if not recorded).
 * @param path peers on the PUT path (or NULL if not recorded).
 * @param desired_replication_level Desired replication level.
 * @param exp Expiration time of the data.
 * @param key Key under which data is to be stored.
 * @param data Pointer to the data carried.
 * @param size Number of bytes in data.
 */
void subscriber_monitor_put_cb (void *cls,
    enum GNUNET_DHT_RouteOption options,
    enum GNUNET_BLOCK_Type type,
    uint32_t hop_count,
    uint32_t desired_replication_level,
    unsigned int path_length,
    const struct GNUNET_PeerIdentity *path,
    struct GNUNET_TIME_Absolute exp,
    const struct GNUNET_HashCode *key,
    const void *data,
    size_t size)
{
  LOG_DEBUG("Subscriber monitor put callback called %s\n", GNUNET_h2s(key));
  LOG_DEBUG("Subscriber monitor put data %s\n",
            GNUNET_i2s((struct GNUNET_PeerIdentity *) data));

  if (sizeof (struct GNUNET_PeerIdentity) == size)
  {
    if (0 == memcmp (&publisher_conf.identity, data, size))
    {
      result = GNUNET_OK;
      schedule_shutdown_test (0);
    }
  }
}


/**
 * Issue DHT-Monitor for each state and free memory when done
 *
 * @param cls Subscriber_Conf
 * @param key current key code. Will be monitored
 * @param value value in the hash map, expected to bet the proof
 * @return #GNUNET_YES if we should continue to
 *         iterate,
 *         #GNUNET_NO if not.
 */
static int
subscriber_monitor_state_and_free (void *cls,
    const struct GNUNET_HashCode *key,
    void *value)
{
  LOG_DEBUG ("Subscriber monitoring state %s %s\n", value, GNUNET_h2s(key));

  struct Subscriber_Config *sconf = (struct Subscriber_Config *) cls;
  if (NULL == sconf->dht_handle)
  {
    /* Use the provided configuration to connect to the dht */
    sconf->dht_handle = GNUNET_DHT_connect (sconf->cfg, sconf->ht_length);
    if (NULL == sconf->dht_handle)
    {
      LOG_ERROR ("Subscriber can not connect to DHT\n");
      schedule_shutdown_test (0);
      return GNUNET_NO;
    }
  }

  // todo add handle to some dll
  GNUNET_DHT_monitor_start (sconf->dht_handle,
                                    GNUNET_BLOCK_TYPE_TEST,
                                    key,
                                    &subscriber_monitor_get_cb,
                                    &subscriber_monitor_get_response_cb,
                                    &subscriber_monitor_put_cb,
                                    sconf);

  GNUNET_free (value);
  return GNUNET_YES;
}


/**
 * Callback for #GNUNET_REGEX_announce_get_accepting_dht_entries
 *
 * @param cls The closure for the callback
 * @param a The original announcement
 * @param accepting_states A map containing all accepting states, or NULL if
 *        something went terribly wrong
 */
static void
subscriber_monitor_accepting_states (void *cls,
    struct GNUNET_REGEX_Announcement *a,
    struct GNUNET_CONTAINER_MultiHashMap *accepting_states)
{
  LOG_DEBUG ("Subscriber start monitoring states\n");
  struct Subscriber_Config *sconf = (struct Subscriber_Config *) cls;
  GNUNET_CONTAINER_multihashmap_iterate (accepting_states,
                                        &subscriber_monitor_state_and_free,
                                        sconf);
  GNUNET_CONTAINER_multihashmap_destroy (accepting_states);
}


/**
 * This is where the test logic should be, at least that part of it that uses
 * the DHT of peer "0".
 *
 * @param cls closure, for the example: NULL
 * @param op should be equal to "dht_op"
 * @param ca_result result of the connect operation, the connection to the DHT
 *    service
 * @param emsg error message, if testbed somehow failed to connect to the DHT.
 */
static void
subscriber_run (void *cls,
  struct GNUNET_TESTBED_Operation *op,
  void *ca_result,
  const char *emsg)
{
  LOG_DEBUG ("Running subscriber\n");

  struct Subscriber_Config *sconf = (struct Subscriber_Config *) cls;

  // Announce the subscriber anonymously
  sconf->regex_announcement = GNUNET_REGEX_announce_with_key (sconf->cfg,
                                                              sconf->topic,
                                                              GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5),
                                                              1,
                                                              GNUNET_CRYPTO_eddsa_key_get_anonymous ());
  if (NULL == sconf->regex_announcement)
  {
    LOG_ERROR ("Subscriber failed announcing interest \"%s\"\n", sconf->topic);
    schedule_shutdown_test (0);
    return;
  }
  LOG_DEBUG ("Subscriber announced interest \"%s\"\n", sconf->topic);

  int get_result = GNUNET_REGEX_announce_get_accepting_dht_entries (sconf->regex_announcement,
                                                                    &subscriber_monitor_accepting_states,
                                                                    sconf);
  if (GNUNET_YES != get_result)
  {
    LOG_ERROR ("Subscriber failed initiating accepting state lookup\n");
    schedule_shutdown_test (0);
    return;
  }
}


/**
 * shuts down the subscriber
 *
 * @param cls The Subscriber_Config
 * @param op_result ignored
 *
 * This gets called when the shutdown task runs
 */
static void
subscriber_da (void *cls, void *op_result)
{
  struct Subscriber_Config *sconf = (struct Subscriber_Config *) cls;

  if (NULL != sconf->regex_announcement)
  {
    GNUNET_REGEX_announce_cancel(sconf->regex_announcement);
    sconf->regex_announcement = NULL;
  }

  if (NULL != sconf->dht_handle)
  {
    GNUNET_DHT_disconnect (sconf->dht_handle);
    sconf->dht_handle = NULL;
  }
}


/**
 * Stores the given configuration in the master Subscriber_Conf struct
 *
 * @param cls closure
 * @param cfg peer configuration
 *
 * @return The Subscriber_Conf struct
 */
static void *
subscriber_ca (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct Subscriber_Config *sconf = (struct Subscriber_Config *) cls;
  sconf->cfg = cfg;
  GNUNET_CRYPTO_get_peer_identity(cfg, &sconf->identity);

  LOG_DEBUG("Subscriber peer ID is %s\n", GNUNET_i2s(&sconf->identity));

  return cls;
}


/**
 * Initialize given peer as a subscriber
 *
 * @param peer The peer to initialize
 * @param conf The config structure for the peer
 */
static void
start_subscriber (struct GNUNET_TESTBED_Peer *subscriber,
    struct Subscriber_Config *conf)
{
  LOG_DEBUG ("Starting Subscriber\n");

  conf->ht_length = HT_LENGTH_DEFAULT;
  conf->topic = "news/(gnunet|wikileaks)";

  /* connect to a peers service */
  conf->op = GNUNET_TESTBED_service_connect (NULL, /* Closure for operation */
      subscriber, /* The peer whose service to connect to */
      NULL, /* The name of the service */
      &subscriber_run, /* callback to call after a handle to service is opened */
      conf, /* closure for the above callback */
      &subscriber_ca, /* callback to call with peer's configuration; this should open the needed service connection */
      &subscriber_da, /* callback to be called when closing the opened service connection */
      conf); /* closure for the above two callbacks */
}


/**
 * DHT put continuation, called after the put has successfully sent out.
 *
 * @param cls ignored
 * @param success GNUNET_OK if the PUT was transmitted, GNUNET_NO on timeout,
 *        GNUNET_SYSERR on disconnect from service after the PUT message was
 *        transmitted (so we don't know if it was received or not)
 */
static void
publisher_put_dht_signal_done (void *cls,
                               int success)
{
  struct Publisher_Config *pconf = (struct Publisher_Config *) cls;
  pconf->put_handle = NULL;

  if (GNUNET_OK != success)
  {
    LOG_ERROR("Publisher failed putting DHT Signal\n");
    schedule_shutdown_test(0);
  }
}


/**
 * Put a signal in the DHT for every matching regex
 *
 * @param cls Closure provided in #GNUNET_REGEX_search.
 * @param id Peer providing a regex that matches the string.
 * @param get_path Path of the get request.
 * @param get_path_length Lenght of @a get_path.
 * @param put_path Path of the put request.
 * @param put_path_length Length of the @a put_path.
 *
 * Search callback function, invoked for every result that was found. But if we
 * already have a DHT put handle every consequent call will be ignored.
 */
static void
publisher_put_dht_signal(void *cls,
                         const struct GNUNET_PeerIdentity *id,
                         const struct GNUNET_PeerIdentity *get_path,
                         unsigned int get_path_length,
                         const struct GNUNET_PeerIdentity *put_path,
                         unsigned int put_path_length,
                         const struct GNUNET_HashCode *key)
{
  struct Publisher_Config *pconf = (struct Publisher_Config *) cls;

  if (NULL != pconf->put_handle)
  {
    /*
     * Only add a new signal if we are currently not putting in the DHT.
     * Because unfortunately this code is not capable of handling simultaneous
     * PUTs.
     */
    return;
  }

  // check if this was the anonymous peer!
  struct GNUNET_CRYPTO_EddsaPublicKey anon_pkey;
  GNUNET_CRYPTO_eddsa_key_get_public (GNUNET_CRYPTO_eddsa_key_get_anonymous (),
                                      &anon_pkey);
  if (0 != memcmp (&id->public_key, &anon_pkey, sizeof (struct GNUNET_CRYPTO_EddsaPublicKey)))
  {
#if 0
    LOG_ERROR ("Publisher found announcement from %s\n", GNUNET_i2s(id));
#endif
    // schedule_shutdown_test (0);
    return;
  }
  LOG_DEBUG("Publisher finds anonymous annonucement\n");
  LOG_DEBUG("Publisher puts signal for key %s\n", GNUNET_h2s(key));

  if (NULL == pconf->dht_handle)
  {
    /* Use the provided configuration to connect to the dht */
    pconf->dht_handle = GNUNET_DHT_connect (pconf->cfg, pconf->ht_length);
    if (NULL == pconf->dht_handle)
    {
      LOG_ERROR ("Publisher can not connect to DHT\n");
      schedule_shutdown_test (0);
      return;
    }
  }

  pconf->put_handle = GNUNET_DHT_put (pconf->dht_handle,
            key, // key
            2, // repl_lvl
            GNUNET_DHT_RO_NONE, // options
            GNUNET_BLOCK_TYPE_TEST , // type
            sizeof (struct GNUNET_PeerIdentity), // size
            &pconf->identity, // data
            GNUNET_TIME_UNIT_FOREVER_ABS, // expiry
            GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 1), //timeout
            publisher_put_dht_signal_done, // continuation
            pconf); // closure
  if (NULL == pconf->put_handle)
  {
    LOG_ERROR ("Publisher can not put Info into DHT\n");
    schedule_shutdown_test (0);
    return;
  }
}


/**
 * This is where the test logic should be, at least that part of it that uses
 * the DHT of peer "0".
 *
 * @param cls closure, for the example: NULL
 * @param op should be equal to "dht_op"
 * @param ca_result result of the connect operation, the connection to the DHT
 *    service
 * @param emsg error message, if testbed somehow failed to connect to the DHT.
 */
static void
publisher_run(void *cls,
  struct GNUNET_TESTBED_Operation *op,
  void *ca_result,
  const char *emsg)
{
  LOG_DEBUG ("Running publisher\n");

  struct Publisher_Config *pconf = (struct Publisher_Config *) cls;

  // Search for the Subscribers
  pconf->regex_search = GNUNET_REGEX_search(pconf->cfg,
                                            pconf->topic,
                                            &publisher_put_dht_signal,
                                            pconf);
  if (NULL == pconf->regex_search)
  {
    LOG_ERROR("Publisher can not do REGEX search \"%s\"\n", pconf->topic);
    schedule_shutdown_test(0);
    return;
  }
  LOG_DEBUG("Publisher does REGEX search \"%s\"\n", pconf->topic);
}


/**
 * Stores the given configuration in the master Publisher_Conf struct
 *
 * @param cls closure
 * @param cfg peer configuration
 *
 * @return The Publisher_Conf struct
 */
static void *
publisher_ca (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct Publisher_Config *pconf = (struct Publisher_Config *) cls;
  pconf->cfg = cfg;
  GNUNET_CRYPTO_get_peer_identity(cfg, &pconf->identity);

  LOG_DEBUG("Publisher peer ID is %s\n", GNUNET_i2s(&pconf->identity));
  return cls;
}


/**
 * shuts down the publisher
 *
 * @param cls The Publisher_Config
 * @param op_result ignored
 *
 * This gets called when the shutdown task runs
 */
static void
publisher_da (void *cls, void *op_result)
{
  struct Publisher_Config *pconf = (struct Publisher_Config *) cls;

  if (NULL != pconf->dht_handle)
  {
    if (NULL != pconf->put_handle)
    {
      GNUNET_DHT_put_cancel(pconf->put_handle);
    }
    GNUNET_DHT_disconnect (pconf->dht_handle);
    pconf->dht_handle = NULL;
  }
  if (NULL != pconf->regex_search)
  {
    GNUNET_REGEX_search_cancel(pconf->regex_search);
    pconf->regex_search = NULL;
  }

  pconf->op = NULL;
}


/**
 * Initialize given peer as a publisher
 *
 * @param peer The peer to initialize
 * @param conf The config structure for the peer
 */
static void
start_publisher (struct GNUNET_TESTBED_Peer *publisher,
    struct Publisher_Config *conf)
{
  LOG_DEBUG ("Starting Publisher\n");

  conf->ht_length = HT_LENGTH_DEFAULT;
  conf->topic = "news/wikileaks";

  /* connect to a peers service */
  conf->op = GNUNET_TESTBED_service_connect (NULL, /* Closure for operation */
      publisher, /* The peer whose service to connect to */
      NULL, /* The name of the service */
      &publisher_run, /* callback to call after a handle to service is opened */
      conf, /* closure for the above callback */
      &publisher_ca, /* callback to call with peer's configuration; this should open the needed service connection */
      &publisher_da, /* callback to be called when closing the opened service connection */
      conf); /* closure for the above two callbacks */
}


/**
 * Main function inovked from TESTBED once all of the peers are up and running.
 * This one then connects just to the DHT service of peer 0.
 *
 * @param cls closure
 * @param h the run handle
 * @param num_peers size of the 'peers' array
 * @param peers started peers for the test
 * @param links_succeeded number of links between peers that were created
 * @param links_failed number of links testbed was unable to establish
 */
static void
run_test (void *cls,
    struct GNUNET_TESTBED_RunHandle *h,
    unsigned int num_peers,
    struct GNUNET_TESTBED_Peer **peers,
    unsigned int links_succeeded,
    unsigned int links_failed)
{
  GNUNET_assert (NUM_PEERS == num_peers);
  GNUNET_assert (1 < NUM_PEERS);

  // First set a time limit for the simulation
  schedule_shutdown_test (600);

  // The publisher will do a regex search for a specific string to see if he
  // finds a subscriber. As soon as he finds one, he will do a DHT-put to
  // announce his peer ID under the same DHT-Key as the accept state
  struct GNUNET_TESTBED_Peer *publisher = peers[0];
  start_publisher (publisher, &publisher_conf);

  // Start the subscriber. It will perform an anonymous announcment and then
  // monitor the DHT to addition by the publisher!
  struct GNUNET_TESTBED_Peer *subscriber = peers[1];
  start_subscriber (subscriber, &subscriber_conf);
}


int
main (int argc, char **argv)
{
  int ret;
  ret = GNUNET_TESTBED_test_run ("test-regex-anonymous-api", /* test case name */
      "test_regex_anonymous_api.conf", /* template configuration */
      NUM_PEERS, /* number of peers to start */
      0LL, /* Event mask -set to 0 for no event notifications */
      NULL, /* Controller event callback */
      NULL, /* Closure for controller event callback */
      &run_test, /* continuation callback to be called when testbed setup is complete */
      NULL); /* Closure for the run_test callback */

  if ((GNUNET_OK != ret) || (GNUNET_OK != result)) {
    LOG_ERROR("FAIL: (╯°□°）╯︵ ┻━┻\n");
    return 1;
  }
  LOG_DEBUG("SUCCESS: ＼(^▽^＠)ノ\n");
  return 0;
}
