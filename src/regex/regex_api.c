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
   * Message we're sending to the service.
   */
  struct AnnounceMessage msg;
};


static int
send_announcement_to_service (struct GNUNET_REGEX_Announcement *a);


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
  return message_len;
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
  a->active_transmission = NULL;
  a->msg.header.type = htons (GNUNET_MESSAGE_TYPE_REGEX_ANNOUNCE);
  a->msg.header.size = htons (slen + sizeof (struct AnnounceMessage));
  a->msg.compression = htons (compression);
  a->msg.reserved = htons (0);
  if(NULL == key)
  {
    memset (&a->msg.key, htons (0), sizeof (a->msg.key));
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
