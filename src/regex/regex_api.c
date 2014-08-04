/*
     This file is part of GNUnet
     (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file regex/regex_api.c
 * @brief access regex service to advertise capabilities via regex and discover
 *        respective peers using matching strings
 * @author Maximilian Szengel
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_util_lib.h"
#include "gnunet_regex_service.h"
#include "regex_ipc.h"

/**
 * Stores context for Accepting State lookups in the DHT
 */
struct GNUNET_REGEX_Announcement_Accepting_Dht
{
  /**
   * The callback when we have a response
   */
  GNUNET_REGEX_Announce_Dht_Handler callback;

  /**
   * Closure for the callback
   */
  void *callback_cls;

  /**
   * The message sent to the service
   */
  struct DhtKeyRequestMessage dht_request_msg;
};


/**
 * Handle to store cached data about a regex announce.
 */
struct GNUNET_REGEX_Announcement
{
  /**
   * Connection to the regex service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * If this is not NULL the client is currently in progress of transmitting
   * data to the service
   */
  struct GNUNET_CLIENT_TransmitHandle *active_transmission;

  /**
   * If not NULL, a request to get the accepting states has been run for this
   * announcement
   */
  struct GNUNET_REGEX_Announcement_Accepting_Dht *dht_request;

  /**
   * Message we're sending to the service.
   */
  struct AnnounceMessage msg;
};


static int
send_announcement_to_service (struct GNUNET_REGEX_Announcement *a);


/**
 * Check if the given announcement has a scheduled DhtKeyRequest
 *
 * @param a The announcement to check
 *
 * @return GNUNET_YES if it has one, GNUNET_NO otherwise
 *
 * Lookups can be scheduled if the connection is still busy transmitting the
 * initial announce when the DHT request was called by the user.
 */
static int
has_pending_dht_request (struct GNUNET_REGEX_Announcement *a)
{
  if (NULL != a->dht_request)
  {
    return GNUNET_YES;
  }

  return GNUNET_NO;
}


/**
 * Parse a single DHT Key, Proof pair
 *
 * @param cursor The current position of parsing
 * @param map The map to fill
 *
 * @return The next unparsed byte
 *
 * This will expect a hashcode to be at the position of cursor and a
 * '\0'-terminated string at the end of it. The return value will be the next
 * byte after the '\0'-terminator.
 *
 * A copy of the proof will be made and put into the map.
 */
static uint8_t *
parse_next_hashcode_proof_pair (const uint8_t *cursor,
                                struct GNUNET_CONTAINER_MultiHashMap *map)
{
  struct GNUNET_HashCode *key = (struct GNUNET_HashCode *) cursor;
  char *proof = (char *) &key[1];
  char *duplicate  = GNUNET_strdup (proof);

  int put_ret = GNUNET_CONTAINER_multihashmap_put (map,
                                                   key,
                                                   duplicate,
                                                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  if (GNUNET_OK != put_ret)
  {
    if (NULL != duplicate)
    {
      GNUNET_free (duplicate);
    }
    return NULL;
  }

  return ((uint8_t *) proof) + strlen (proof) + 1;
}


/**
 * Fills the given map with the DHT Key, Proof pairs from the buffer
 *
 * @param map The map to fill
 * @param buffer The buffer wit the DHT Key, Proof pairs
 * @param buffer_size The size of the buffer in bytes
 * @param num_entries The amount of entries in the buffer
 *
 * @return GNUNET_YES if everything was good, GNUNET_NO if the buffer could not
 *         be parsed
 */
static int
fill_map_with_key_proof_from_buffer (struct GNUNET_CONTAINER_MultiHashMap *map,
                                     const void *buffer,
                                     size_t buffer_size,
                                     uint16_t num_entries)
{
  // Calculate the expected end of message from length
  uint8_t *end_of_msg = ((uint8_t *) buffer) + buffer_size;

  uint16_t i;
  uint8_t *cursor = (uint8_t *) buffer;
  for (i = 0; i < num_entries; i++)
  {
    cursor = parse_next_hashcode_proof_pair (cursor, map);
    if (NULL == cursor || end_of_msg < cursor)
    {
      return GNUNET_NO;
    }
  }

  // When we are done with the loop some conditions have to hold
  if (end_of_msg != cursor)
  {
    return GNUNET_NO;
  }
  if (num_entries != GNUNET_CONTAINER_multihashmap_size (map))
  {
    return GNUNET_NO;
  }

  return GNUNET_YES;
}


/**
 * Frees the space of all map values
 *
 * @param cls Don't care
 * @param key The key of the value. Don't care
 * @param value The value to be freed
 *
 * @return Always GNUNET_YES
 */
static int
destroy_proofs_iterator (void *cls,
                         const struct GNUNET_HashCode *key,
                         void *value)
{
  if (NULL != value)
  {
    GNUNET_free (value);
  }
  return GNUNET_YES;
}


/**
 * Parse the response from the REGEX service
 *
 * @param msg The message from the service
 *
 * @return A hashmap containing the DHT keys and proofs, or NULL if the message
 *         could not be parsed
 */
static struct GNUNET_CONTAINER_MultiHashMap *
parse_dht_response (const struct GNUNET_MessageHeader *msg)
{
  int is_right_type = GNUNET_MESSAGE_TYPE_REGEX_ACCEPTING_DHT_ENTRIES == ntohs (msg->type);
  int is_large_enough = ntohs (msg->size) >= sizeof (struct DhtKeyResponseMessage);
  if (!is_right_type || !is_large_enough)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "DhtKeyResponse short\n");
    return NULL;
  }
  struct DhtKeyResponseMessage *response = (struct DhtKeyResponseMessage *) msg;

  uint16_t num_entries = ntohs (response->num_entries);
  struct GNUNET_CONTAINER_MultiHashMap *map;
  map = GNUNET_CONTAINER_multihashmap_create (num_entries, GNUNET_NO);

  size_t buffer_size = ntohs (msg->size) - sizeof (struct DhtKeyResponseMessage);
  if (GNUNET_NO == fill_map_with_key_proof_from_buffer (map, &response[1], buffer_size, num_entries))
  {
    GNUNET_CONTAINER_multihashmap_iterate (map,
                                           &destroy_proofs_iterator,
                                           NULL);
    GNUNET_CONTAINER_multihashmap_destroy (map);
    map = NULL;
  }

  return map;
}


/**
 * Handle the response we get from the REGEX service
 *
 * @param cls The announcement for which the accepting DHT keys have been
 *        looked up for
 * @param msg The response from the service
 *
 * This will parse the message, and call the callback.
 */
static void
handle_accepting_dht_response (void *cls,
                               const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_REGEX_Announcement *a = (struct GNUNET_REGEX_Announcement *) cls;
  if (NULL == a || NULL == a->dht_request || NULL == a->dht_request->callback)
  {
    // Weird, none of them should be NULL
    return;
  }

  struct GNUNET_CONTAINER_MultiHashMap *map;
  map =  parse_dht_response (msg);
  a->dht_request->callback (a->dht_request->callback_cls, a, map);
}


/**
 * Send the DhtKeyRequest to the REGEX service
 *
 * @param a The announcement with the DhtKeyRequest to be sent
 */
static int
send_accepting_dht_request_to_service (struct GNUNET_REGEX_Announcement *a)
{
  if (NULL == a->client)
  {
    return GNUNET_NO;
  }

  int ret = GNUNET_CLIENT_transmit_and_get_response (a->client,
                                           &a->dht_request->dht_request_msg.header,
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           GNUNET_YES,
                                           &handle_accepting_dht_response,
                                           a);

  if (GNUNET_OK == ret)
  {
    return GNUNET_YES;
  }
  return GNUNET_NO;
}


/**
 * Function called to notify a client about the connection begin ready
 * to queue more data.  @a buf will be NULL and @a size zero if the
 * connection was closed for writing in the meantime.
 *
 * @param cls closure
 * @param size number of bytes available in @a buf
 * @param buf where the callee should write the message
 * @return number of bytes written to @a buf
 */
static size_t
announce_transmit_ready_cb (void *cls,
                            size_t size,
                            void *buf)
{
  struct GNUNET_REGEX_Announcement *a = (struct GNUNET_REGEX_Announcement *) cls;
  size_t message_len = ntohs (a->msg.header.size);

  if (NULL == buf || size < message_len)
  {
    // close connection and retry
    GNUNET_CLIENT_disconnect (a->client);
    a->client = NULL;

    send_announcement_to_service (a);
    return 0;
  }

  // Consider the transmission as complete because it is to late to call
  // cancel for the transmission anyhow.
  a->active_transmission = NULL;
  memcpy (buf, &a->msg.header, message_len);

  // Connection is free now so check if we need to do a DHT lookup
  if (has_pending_dht_request (a))
  {
    send_accepting_dht_request_to_service (a);
  }

  return message_len;
}


/**
 * Schedule a DHT lookup for the given announcement
 *
 * @param a The announcement to look up the accepting DHT states
 *
 * @return GNUNET_YES if the transmission could be scheduled/done, GNUNET_NO
 *         otherwise
 *
 * The passed @a must be already prepared. Depending on the status of the
 * connection this will either schedule a transmission to the regex service or
 * perform it right away.
 */
static int
schedule_send_accepting_dht_request (struct GNUNET_REGEX_Announcement *a)
{
  if (NULL == a->active_transmission)
  {
    // Connection is not busy, send right away!
    return send_accepting_dht_request_to_service (a);
  }

  // Nothing has to be done for it to be scheduled. If attached to the
  // Announcement it will automatically be send when the connection is free
  return GNUNET_YES;
}


/**
 * Send the given announcement to the REGEX service
 *
 * @param a The announcement to send
 *
 * @return GNUNET_YES on success, GNUNET_FALSE otherwise
 *
 * If the client is not connected to the service this will try to open a
 * connection automatically.
 *
 * This will also schedule retransmissions if necessary until either the
 * message was sent successfully or the Announcement has been cancelled.
 */
static int
send_announcement_to_service (struct GNUNET_REGEX_Announcement *a)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "send_announcement_to_service\n");

  if (NULL == a->client)
  {
    a->client = GNUNET_CLIENT_connect ("regex", a->cfg);
    if (NULL == a->client)
    {
      GNUNET_REGEX_announce_cancel (a);
      return GNUNET_NO;
    }
  }

  struct GNUNET_CLIENT_TransmitHandle *ath;
  ath = GNUNET_CLIENT_notify_transmit_ready (a->client,
                                       ntohs (a->msg.header.size),
                                       GNUNET_TIME_UNIT_FOREVER_REL,
                                       GNUNET_YES,
                                       &announce_transmit_ready_cb,
                                       a);

  if (NULL == ath)
  {
    GNUNET_REGEX_announce_cancel (a);
    return GNUNET_NO;
  }

  a->active_transmission = ath;
  return GNUNET_YES;
}


/**
 * Announce the given peer under the given regular expression.  Does
 * not free resources, must call #GNUNET_REGEX_announce_cancel for
 * that.
 *
 * @param cfg configuration to use
 * @param regex Regular expression to announce.
 * @param refresh_delay after what delay should the announcement be repeated?
 * @param compression How many characters per edge can we squeeze?
 * @return Handle to reuse o free cached resources.
 *         Must be freed by calling #GNUNET_REGEX_announce_cancel.
 */
struct GNUNET_REGEX_Announcement *
GNUNET_REGEX_announce (const struct GNUNET_CONFIGURATION_Handle *cfg,
                       const char *regex,
		       struct GNUNET_TIME_Relative refresh_delay,
                       uint16_t compression)
{
  return GNUNET_REGEX_announce_with_key (cfg,
                                         regex,
                                         refresh_delay,
                                         compression,
                                         NULL);
}


int
GNUNET_REGEX_announce_get_accepting_dht_entries (
    struct GNUNET_REGEX_Announcement *a,
    GNUNET_REGEX_Announce_Dht_Handler callback,
    void *cls)
{
  // Only construct a new DHT Request if there is no saved one.
  // We have to save the DHT Request so that we can free memory when the
  // Announcement is canceled
  if (NULL == a->dht_request)
  {
    // To determine the length of the message do not forget that there is the
    // regex string attached to the end of it
    size_t regex_len = strlen ((const char *) &a[1]) + 1;
    size_t total_len = sizeof (struct GNUNET_REGEX_Announcement_Accepting_Dht) + regex_len;
    size_t message_len = sizeof (struct DhtKeyRequestMessage) + regex_len;

    // Check the message size to make sure it is not to big
    if (GNUNET_SERVER_MAX_MESSAGE_SIZE <= message_len)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("DHT Key get message is too long!\n"));
      GNUNET_break (0);
      return GNUNET_NO;
    }

    // Build the DhtKeyRequestMessage
    struct GNUNET_REGEX_Announcement_Accepting_Dht *dht_request;
    dht_request = GNUNET_malloc(total_len);
    dht_request->callback = callback;
    dht_request->callback_cls = cls;
    dht_request->dht_request_msg.header.type = htons (GNUNET_MESSAGE_TYPE_REGEX_GET_ACCEPTING_DHT_ENTRIES);
    dht_request->dht_request_msg.header.size = htons (message_len);
    dht_request->dht_request_msg.original_announce = a->msg;
    // Be careful to copy all of the AnnounceMessage since it has the REGEX
    // attached to it at the end of the struct
    memcpy (&dht_request[1], &a[1], regex_len);

    // Tag the DHT Request to the announce message so that we can free the
    // memory when the announcement gets canceled
    a->dht_request = dht_request;
  }

  return schedule_send_accepting_dht_request (a);
}


/**
 * Announce this with the given EdDSA key under the given regular expression.
 * Does not free resources, must call #GNUNET_REGEX_announce_cancel for
 * that.
 *
 * @param cfg configuration to use
 * @param regex Regular expression to announce.
 * @param refresh_delay after what delay should the announcement be repeated?
 * @param compression How many characters per edge can we squeeze?
 * @param key The key to be used when not announcing under this peers ID. If
 *        NULL is being passed this method will behave like the regular
 *        GNUNET_REGEX_announce
 * @return Handle to reuse o free cached resources.
 *         Must be freed by calling #GNUNET_REGEX_announce_cancel.
 */
struct GNUNET_REGEX_Announcement *
GNUNET_REGEX_announce_with_key (const struct GNUNET_CONFIGURATION_Handle *cfg,
                       const char *regex,
                       struct GNUNET_TIME_Relative refresh_delay,
                       uint16_t compression,
                       struct GNUNET_CRYPTO_EddsaPrivateKey *key)
{
  struct GNUNET_REGEX_Announcement *a;
  size_t slen;

  slen = strlen (regex) + 1;
  if (slen + sizeof (struct AnnounceMessage) >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Regex `%s' is too long!\n"),
                regex);
    GNUNET_break (0);
    return NULL;
  }

  a = GNUNET_malloc (sizeof (struct GNUNET_REGEX_Announcement) + slen);
  a->cfg = cfg;
  a->client = NULL;
  a->dht_request = NULL;
  a->active_transmission = NULL;
  a->msg.header.type = htons (GNUNET_MESSAGE_TYPE_REGEX_ANNOUNCE);
  a->msg.header.size = htons (slen + sizeof (struct AnnounceMessage));
  a->msg.compression = htons (compression);
  a->msg.reserved = htons (0);
  if(NULL == key)
  {
    memset (&a->msg.key, 0, sizeof (a->msg.key));
  }
  else
  {
    a->msg.key = *key;
  }
  a->msg.refresh_delay = GNUNET_TIME_relative_hton (refresh_delay);
  memcpy (&a[1], regex, slen);

  if (GNUNET_YES == send_announcement_to_service (a))
  {
    return a;
  }
  return NULL;
}


/**
 * Stop announcing the regex specified by the given handle.
 *
 * @param a handle returned by a previous GNUNET_REGEX_announce call.
 */
void
GNUNET_REGEX_announce_cancel (struct GNUNET_REGEX_Announcement *a)
{
  if (NULL != a->active_transmission)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel(a->active_transmission);
  }
  if (NULL != a->client)
  {
    GNUNET_CLIENT_disconnect (a->client);
  }
  if (NULL != a->dht_request)
  {
    GNUNET_free (a->dht_request);
  }
  GNUNET_free (a);
}


/**
 * Handle to store data about a regex search.
 */
struct GNUNET_REGEX_Search
{
  /**
   * Connection to the regex service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Function to call with results.
   */
  GNUNET_REGEX_Found callback;

  /**
   * Closure for @e callback.
   */
  void *callback_cls;

  /**
   * Search message to transmit to the service.
   */
  struct RegexSearchMessage *msg;
};


/**
 * We got a response or disconnect after asking regex
 * to do the search.  Handle it.
 *
 * @param cls the `struct GNUNET_REGEX_Search` to retry
 * @param msg NULL on disconnect
 */
static void
handle_search_response (void *cls,
			const struct GNUNET_MessageHeader *msg);


/**
 * Try sending the search request to regex.  On
 * errors (i.e. regex died), try again.
 *
 * @param s the search to retry
 */
static void
retry_search (struct GNUNET_REGEX_Search *s)
{
  GNUNET_assert (NULL != s->client);
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CLIENT_transmit_and_get_response (s->client,
							  &s->msg->header,
							  GNUNET_TIME_UNIT_FOREVER_REL,
							  GNUNET_YES,
							  &handle_search_response,
							  s));
}


/**
 * We got a response or disconnect after asking regex
 * to do the search.  Handle it.
 *
 * @param cls the 'struct GNUNET_REGEX_Search' to retry
 * @param msg NULL on disconnect, otherwise presumably a response
 */
static void
handle_search_response (void *cls,
			const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_REGEX_Search *s = cls;
  const struct ResultMessage *result;
  uint16_t size;
  uint16_t gpl;
  uint16_t ppl;

  if (NULL == msg)
  {
    GNUNET_CLIENT_disconnect (s->client);
    s->client = GNUNET_CLIENT_connect ("regex", s->cfg);
    retry_search (s);
    return;
  }
  size = ntohs (msg->size);
  if ( (GNUNET_MESSAGE_TYPE_REGEX_RESULT == ntohs (msg->type)) &&
       (size >= sizeof (struct ResultMessage)) )
  {
    result = (const struct ResultMessage *) msg;
    gpl = ntohs (result->get_path_length);
    ppl = ntohs (result->put_path_length);
    if (size == (sizeof (struct ResultMessage) +
		 (gpl + ppl) * sizeof (struct GNUNET_PeerIdentity)))
    {
      const struct GNUNET_PeerIdentity *pid;

      GNUNET_CLIENT_receive (s->client,
			     &handle_search_response, s,
			     GNUNET_TIME_UNIT_FOREVER_REL);
      pid = &result->id;
      s->callback (s->callback_cls,
		   pid,
		   &pid[1], gpl,
		   &pid[1 + gpl], ppl, &result->key);
      return;
    }
  }
  GNUNET_break (0);
  GNUNET_CLIENT_disconnect (s->client);
  s->client = GNUNET_CLIENT_connect ("regex", s->cfg);
  retry_search (s);
}


/**
 * Search for a peer offering a regex matching certain string in the DHT.
 * The search runs until GNUNET_REGEX_search_cancel is called, even if results
 * are returned.
 *
 * @param cfg configuration to use
 * @param string String to match against the regexes in the DHT.
 * @param callback Callback for found peers.
 * @param callback_cls Closure for @c callback.
 * @return Handle to stop search and free resources.
 *         Must be freed by calling GNUNET_REGEX_search_cancel.
 */
struct GNUNET_REGEX_Search *
GNUNET_REGEX_search (const struct GNUNET_CONFIGURATION_Handle *cfg,
		     const char *string,
                     GNUNET_REGEX_Found callback,
                     void *callback_cls)
{
  struct GNUNET_REGEX_Search *s;
  size_t slen;

  slen = strlen (string) + 1;
  s = GNUNET_new (struct GNUNET_REGEX_Search);
  s->cfg = cfg;
  s->client = GNUNET_CLIENT_connect ("regex", cfg);
  if (NULL == s->client)
  {
    GNUNET_free (s);
    return NULL;
  }
  s->callback = callback;
  s->callback_cls = callback_cls;
  s->msg = GNUNET_malloc (sizeof (struct RegexSearchMessage) + slen);
  s->msg->header.type = htons (GNUNET_MESSAGE_TYPE_REGEX_SEARCH);
  s->msg->header.size = htons (sizeof (struct RegexSearchMessage) + slen);
  memcpy (&s->msg[1], string, slen);
  retry_search (s);
  return s;
}


/**
 * Stop search and free all data used by a GNUNET_REGEX_search call.
 *
 * @param s Handle returned by a previous GNUNET_REGEX_search call.
 */
void
GNUNET_REGEX_search_cancel (struct GNUNET_REGEX_Search *s)
{
  GNUNET_CLIENT_disconnect (s->client);
  GNUNET_free (s->msg);
  GNUNET_free (s);
}


/* end of regex_api.c */
