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
 * @file regex/gnunet-service-regex.c
 * @brief service to advertise capabilities described as regex and to
 *        lookup capabilities by regex
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "regex_internal_lib.h"
#include "regex_ipc.h"


/**
 * Information about one of our clients.
 */
struct ClientEntry
{

  /**
   * Kept in DLL.
   */
  struct ClientEntry *next;

  /**
   * Kept in DLL.
   */
  struct ClientEntry *prev;

  /**
   * Handle identifying the client.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Search handle (if this client is searching).
   */
  struct REGEX_INTERNAL_Search *sh;

  /**
   * Announcement handle (if this client is announcing).
   */
  struct REGEX_INTERNAL_Announcement *ah;

  /**
   * Refresh frequency for announcements.
   */
  struct GNUNET_TIME_Relative frequency;

  /**
   * Task for re-announcing.
   */
  GNUNET_SCHEDULER_TaskIdentifier refresh_task;

};


/**
 * Connection to the DHT.
 */
static struct GNUNET_DHT_Handle *dht;

/**
 * Handle for doing statistics.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Head of list of clients.
 */
static struct ClientEntry *client_head;

/**
 * End of list of clients.
 */
static struct ClientEntry *client_tail;

/**
 * Our notification context, used to send back results to the client.
 */
static struct GNUNET_SERVER_NotificationContext *nc;

/**
 * Private key for this peer.
 */
static struct GNUNET_CRYPTO_EddsaPrivateKey *my_private_key;


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
cleanup_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_DHT_disconnect (dht);
  dht = NULL;
  GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
  stats = NULL;
  GNUNET_SERVER_notification_context_destroy (nc);
  nc = NULL;
  GNUNET_free (my_private_key);
  my_private_key = NULL;
}


/**
 * Find the client entry for the client
 *
 * @param client A connected client
 *
 * @return The ClientEntry, or NULL if the client can not be found
 */
static struct ClientEntry *
find_client_entry (struct GNUNET_SERVER_Client *client)
{
  struct ClientEntry *ce;
  struct ClientEntry *nx;

  nx = client_head;
  for (ce = nx; NULL != ce; ce = nx)
  {
    nx = ce->next;
    if (ce->client == client)
    {
      return ce;
    }
  }

  return NULL;
}


/**
 * A client disconnected.  Remove all of its data structure entries.
 *
 * @param cls closure, NULL
 * @param client identification of the client
 */
static void
handle_client_disconnect (void *cls, struct GNUNET_SERVER_Client *client)
{
  struct ClientEntry *ce;
  ce = find_client_entry (client);

  // Notice that there might not be a client entry if the message of the client
  // was illegal. He will still disconnect though!
  if (NULL != ce)
  {
    if (GNUNET_SCHEDULER_NO_TASK != ce->refresh_task)
    {
      GNUNET_SCHEDULER_cancel (ce->refresh_task);
      ce->refresh_task = GNUNET_SCHEDULER_NO_TASK;
    }
    if (NULL != ce->ah)
    {
      REGEX_INTERNAL_announce_cancel (ce->ah);
      ce->ah = NULL;
    }
    if (NULL != ce->sh)
    {
      REGEX_INTERNAL_search_cancel (ce->sh);
      ce->sh = NULL;
    }
    GNUNET_CONTAINER_DLL_remove (client_head, client_tail, ce);
    GNUNET_free (ce);
  }
}


/**
 * Periodic task to refresh our announcement of the regex.
 *
 * @param cls the 'struct ClientEntry' of the client that triggered the
 *        announcement
 * @param tc scheduler context
 */
static void
reannounce (void *cls,
	    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ClientEntry *ce = cls;

  REGEX_INTERNAL_reannounce (ce->ah);
  ce->refresh_task = GNUNET_SCHEDULER_add_delayed (ce->frequency,
						   &reannounce,
						   ce);
}


/**
 * Checks if an AnnounceMessage contains an EdDSA key.
 *
 * Any key that in different from memset(key, htons(0), sizeof(key)) will be
 * considered valid.
 *
 * @param am The message to parse
 *
 * @return A pointer to the EdDSA key or NULL if there is no valid key
 */
static struct GNUNET_CRYPTO_EddsaPrivateKey *
get_eddsa_key (const struct AnnounceMessage *am)
{
  struct GNUNET_CRYPTO_EddsaPrivateKey zero_key;
  memset (&zero_key, 0, sizeof (zero_key));
  if (0 == memcmp (&am->key, &zero_key, sizeof (zero_key)))
  {
    return NULL;
  }
  return &am->key;
}


/**
 * Parse a message to see if it is a valid announce message
 *
 * @param message The message to parse
 *
 * @return A pointer to the regex of the message, or NULL if the message could
 *         not be parsed
 */
static const char *
parse_announce_message (const struct GNUNET_MessageHeader *message)
{
  uint16_t size = ntohs (message->size);
  const struct AnnounceMessage *am = (const struct AnnounceMessage *) message;
  const char *regex = (const char *) &am[1];

  if ( (size <= sizeof (struct AnnounceMessage)) ||
       ('\0' != regex[size - sizeof (struct AnnounceMessage) - 1]) )
  {
    return NULL;
  }

  return regex;
}


/**
 * Parse the given message to see if it is a valid DHT Key Request
 *
 * @param message The message to parse
 *
 * @return A pointer to the request, or NULL if the message could not be parsed
 *
 * This will also validate the attached AnnouncementMessage
 */
static const struct DhtKeyRequestMessage *
parse_dht_key_request (const struct GNUNET_MessageHeader *msg)
{
  // Check the message to be big enough to actually carry a DHT message
  if (sizeof (struct DhtKeyRequestMessage) > ntohs (msg->size))
  {
    return NULL;
  }

  // First some message casting
  const struct DhtKeyRequestMessage *dht_msg;
  dht_msg = (const struct DhtKeyRequestMessage *) msg;
  const struct GNUNET_MessageHeader *maybe_announce_msg;
  maybe_announce_msg = (const struct GNUNET_MessageHeader *) &dht_msg->original_announce;

  // Then check if the announce is valid
  if (NULL == parse_announce_message (maybe_announce_msg))
  {
    return NULL;
  }

  size_t expected_size = sizeof (struct GNUNET_MessageHeader) + ntohs (maybe_announce_msg->size);
  if (expected_size != ntohs (msg->size))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Illegal DHT Message Size: Expected %d Actual %d\n",
                expected_size,
                ntohs (msg->size));
    return NULL;
  }

  return dht_msg;
}


/**
 * Fill the response buffer with the values from the DHT and free memory of the
 * HashMap
 *
 * @param cls A pointer to the pointer to the buffer
 * @param key The key
 * @param value The proof as a '\0' terminated string. Will be freed when
 *        copied to buffer.
 *
 * @cls is points to the following
 *
 *     next free byte in buf <-- buf_ptr <-- cls
 *
 * So dereference it to get a a pointer to the next free byte in the buffer.
 * Then when the data has been copied update buf_ptr to make sure the next
 * iteration also know the next free byte in the buffer.
 */
static int
fill_dht_response_buffer(void *cls,
                         const struct GNUNET_HashCode *key,
                         void *value)
{
  uint8_t **buf_ptr_ptr = (uint8_t **) cls;
  uint8_t *buf = *buf_ptr_ptr;

  memcpy(buf, key, sizeof (struct GNUNET_HashCode));
  memcpy(buf + sizeof (struct GNUNET_HashCode), value, strlen ((char *) value) + 1);

  buf += sizeof (struct GNUNET_HashCode) + strlen ((char *) value) + 1;
  *buf_ptr_ptr = buf;

  // The value is in the buffer so free the memory of the HashMap value
  GNUNET_free (value);

  return GNUNET_YES;
}


/**
 * Prepare the response and send it to the client
 *
 * @param client The client to respond to
 * @param accepting_keys A hashmap containing all accepting DHT keys and the
 *        proofs as value
 * @param map_size_bytes The amount of bytes stored in the map (keys and
 *        strings combined)
 */
static void
prepare_and_send_dht_response (struct GNUNET_SERVER_Client *client,
                               struct GNUNET_CONTAINER_MultiHashMap *accepting_keys,
                               int32_t map_size_bytes)
{
  size_t total_msg_size = sizeof (struct DhtKeyResponseMessage) + map_size_bytes;
  if (GNUNET_SERVER_MAX_MESSAGE_SIZE < total_msg_size)
  {
    return;
  }

  struct DhtKeyResponseMessage *msg = GNUNET_malloc (total_msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_REGEX_ACCEPTING_DHT_ENTRIES);
  msg->header.size = htons (total_msg_size);
  msg->num_entries = htons (GNUNET_CONTAINER_multihashmap_size (accepting_keys));

  // Now build the return message.
  // We allocate the buffer here and then pass a pointer to the buffer to the
  // iterator. The idea is that the iterator always gets a pointer, to the
  // pointer that points to the next free byte in the buffer
  //
  //   buf (always points to the beginning of the buffer)
  //   |
  //   |
  // +---------------------------+
  // | B | u | f | f | e | r | … |
  // +---------------------------+
  //       ^
  //       |
  //       buf_cls (advances as buffer gets filled) <-- pointer to buf_cls
  //                                                    (passed as a closure)
  uint8_t *buf = (uint8_t *) &msg[1];
  uint8_t *buf_cls = buf;
  int iterate_result = GNUNET_CONTAINER_multihashmap_iterate (accepting_keys,
                                         &fill_dht_response_buffer,
                                         &buf_cls);
  GNUNET_assert (iterate_result == GNUNET_CONTAINER_multihashmap_size (accepting_keys));
  GNUNET_CONTAINER_multihashmap_destroy (accepting_keys);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
             "0x%x + 0x%x = 0x%x; 0x%x\n",
             buf,
             map_size_bytes,
             buf + map_size_bytes,
             buf_cls);
  GNUNET_assert (buf + map_size_bytes == buf_cls);

  GNUNET_SERVER_notification_context_unicast (nc, client,
                   &msg->header, GNUNET_NO);

  GNUNET_free (msg);
}


/**
 * Handle the accepting DHT lookup request
 *
 * @param cls Always NULL
 * @param client The client that sent the message
 * @param message The lookup request from the client
 *
 * This will issue the internal DFA lookup and queue the sending of the
 * response if the lookup was successful.
 */
static void
handle_dht_key_get_message (void *cls,
                            struct GNUNET_SERVER_Client *client,
                            const struct GNUNET_MessageHeader *message)
{
  const struct DhtKeyRequestMessage *dht_msg = parse_dht_key_request(message);
  if (NULL == dht_msg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Got broken DHT Message\n");
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got valid DHT Message\n");

  // Based on the announce message and the connected client, try to find the
  // internal announcement in the client list (client_head, client_tail)
  struct ClientEntry *ce = find_client_entry (client);
  if (NULL == ce)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No client entry for DHT Message\n");
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  // Then you can call regex iterate to find all the accepting states
  struct GNUNET_CONTAINER_MultiHashMap *accepting_keys;
  accepting_keys = GNUNET_CONTAINER_multihashmap_create(1, GNUNET_NO);
  int32_t map_size = REGEX_INTERNAL_announce_get_accepting_dht_entries (ce->ah, accepting_keys);
  if (map_size < 0)
  {
    GNUNET_CONTAINER_multihashmap_destroy (accepting_keys);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Internal DHT key lookup failed\n");
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Have %d = %d * %d + x = %d + x bytes in the map\n",
                map_size,
                GNUNET_CONTAINER_multihashmap_size (accepting_keys),
                sizeof (struct GNUNET_HashCode),
                sizeof (struct GNUNET_HashCode) * GNUNET_CONTAINER_multihashmap_size (accepting_keys));

  // The lookup worked out, so ACK this and store the client to send him the
  // response once we have formatted it
  GNUNET_SERVER_notification_context_add (nc, client);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);

  prepare_and_send_dht_response (client, accepting_keys, map_size);
}


/**
 * Handle ANNOUNCE message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_announce (void *cls,
		 struct GNUNET_SERVER_Client *client,
		 const struct GNUNET_MessageHeader *message)
{
  const struct AnnounceMessage *am;
  const char *regex;
  struct ClientEntry *ce;
  struct GNUNET_CRYPTO_EddsaPrivateKey *key;

  regex = parse_announce_message (message);
  if (NULL == regex) {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  am = (const struct AnnounceMessage *) message;

  // Get the private EdDSA key
  // If the message did not contain a valid key it will return NULL. So check
  // the return value and assign a default key.
  key = get_eddsa_key (am);
  if(NULL == key)
  {
    key = my_private_key;
  }

  ce = GNUNET_new (struct ClientEntry);
  ce->client = client;
  ce->frequency = GNUNET_TIME_relative_ntoh (am->refresh_delay);
  ce->refresh_task = GNUNET_SCHEDULER_add_delayed (ce->frequency,
						   &reannounce,
						   ce);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Starting to announce regex `%s' every %s\n",
	      regex,
	      GNUNET_STRINGS_relative_time_to_string (ce->frequency,
						      GNUNET_NO));
  ce->ah = REGEX_INTERNAL_announce (dht,
				    key,
				    regex,
				    ntohs (am->compression),
				    stats);
  if (NULL == ce->ah)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_cancel (ce->refresh_task);
    GNUNET_free (ce);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  GNUNET_assert (NULL == find_client_entry (client));
  GNUNET_CONTAINER_DLL_insert (client_head,
			       client_tail,
			       ce);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle result, pass it back to the client.
 *
 * @param cls the struct ClientEntry of the client searching
 * @param id Peer providing a regex that matches the string.
 * @param get_path Path of the get request.
 * @param get_path_length Lenght of get_path.
 * @param put_path Path of the put request.
 * @param put_path_length Length of the put_path.
 * @param key The DHT key where the peer was found.
 */
static void
handle_search_result (void *cls,
		      const struct GNUNET_PeerIdentity *id,
		      const struct GNUNET_PeerIdentity *get_path,
		      unsigned int get_path_length,
		      const struct GNUNET_PeerIdentity *put_path,
		      unsigned int put_path_length,
		      const struct GNUNET_HashCode *key)
{
  struct ClientEntry *ce = cls;
  struct ResultMessage *result;
  struct GNUNET_PeerIdentity *gp;
  uint16_t size;

  if ( (get_path_length >= 65536) ||
       (put_path_length >= 65536) ||
       ( (get_path_length + put_path_length) * sizeof (struct GNUNET_PeerIdentity))
       + sizeof (struct ResultMessage) >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  size = (get_path_length + put_path_length) * sizeof (struct GNUNET_PeerIdentity) + sizeof (struct ResultMessage);
  result = GNUNET_malloc (size);
  result->header.size = htons (size);
  result->header.type = htons (GNUNET_MESSAGE_TYPE_REGEX_RESULT);
  result->get_path_length = htons ((uint16_t) get_path_length);
  result->put_path_length = htons ((uint16_t) put_path_length);
  result->id = *id;
  result->key = *key;
  gp = &result->id;
  memcpy (&gp[1],
	  get_path,
	  get_path_length * sizeof (struct GNUNET_PeerIdentity));
  memcpy (&gp[1 + get_path_length],
	  put_path,
	  put_path_length * sizeof (struct GNUNET_PeerIdentity));
  GNUNET_SERVER_notification_context_unicast (nc,
					      ce->client,
					      &result->header, GNUNET_NO);
  GNUNET_free (result);
}


/**
 * Handle SEARCH message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_search (void *cls,
	       struct GNUNET_SERVER_Client *client,
	       const struct GNUNET_MessageHeader *message)
{
  const struct RegexSearchMessage *sm;
  const char *string;
  struct ClientEntry *ce;
  uint16_t size;

  size = ntohs (message->size);
  sm = (const struct RegexSearchMessage *) message;
  string = (const char *) &sm[1];
  if ( (size <= sizeof (struct RegexSearchMessage)) ||
       ('\0' != string[size - sizeof (struct RegexSearchMessage) - 1]) )
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  ce = GNUNET_new (struct ClientEntry);
  ce->client = client;
  ce->sh = REGEX_INTERNAL_search (dht,
				string,
				&handle_search_result,
				ce,
				stats);
  if (NULL == ce->sh)
  {
    GNUNET_break (0);
    GNUNET_free (ce);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  GNUNET_assert (NULL == find_client_entry (client));
  GNUNET_CONTAINER_DLL_insert (client_head,
			       client_tail,
			       ce);
  GNUNET_SERVER_notification_context_add (nc, client);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Process regex requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_announce, NULL, GNUNET_MESSAGE_TYPE_REGEX_ANNOUNCE, 0},
    {&handle_search, NULL, GNUNET_MESSAGE_TYPE_REGEX_SEARCH, 0},
    {&handle_dht_key_get_message, NULL, GNUNET_MESSAGE_TYPE_REGEX_GET_ACCEPTING_DHT_ENTRIES, 0},
    {NULL, NULL, 0, 0}
  };

  my_private_key = GNUNET_CRYPTO_eddsa_key_create_from_configuration (cfg);
  if (NULL == my_private_key)
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  dht = GNUNET_DHT_connect (cfg, 1024);
  if (NULL == dht)
  {
    GNUNET_free (my_private_key);
    my_private_key = NULL;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleanup_task,
                                NULL);
  nc = GNUNET_SERVER_notification_context_create (server, 1);
  stats = GNUNET_STATISTICS_create ("regex", cfg);
  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SERVER_disconnect_notify (server, &handle_client_disconnect, NULL);
}


/**
 * The main function for the regex service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "regex",
                              GNUNET_SERVICE_OPTION_NONE, &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-regex.c */
