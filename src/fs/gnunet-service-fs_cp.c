/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file fs/gnunet-service-fs_cp.c
 * @brief API to handle 'connected peers'
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-fs.h"
#include "gnunet-service-fs_cp.h"

/**
 * How often do we flush trust values to disk?
 */
#define TRUST_FLUSH_FREQ GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5)

/**
 * After how long do we discard a reply?
 */
#define REPLY_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 2)


/**
 * Handle to cancel a transmission request.
 */
struct GSF_PeerTransmitHandle
{

  /**
   * Handle for an active request for transmission to this
   * peer, or NULL (if core queue was full).
   */
  struct GNUNET_CORE_TransmitHandle *cth;

  /**
   * Time when this transmission request was issued.
   */
  struct GNUNET_TIME_Absolute transmission_request_start_time;

  /**
   * Timeout for this request.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Task called on timeout, or 0 for none.
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * Function to call to get the actual message.
   */
  GSF_GetMessageCallback gmc;

  /**
   * Peer this request targets.
   */
  struct GSF_ConnectedPeer *cp;

  /**
   * Closure for 'gmc'.
   */
  void *gmc_cls;

  /**
   * Size of the message to be transmitted.
   */
  size_t size;

  /**
   * GNUNET_YES if this is a query, GNUNET_NO for content.
   */
  int is_query;

  /**
   * Priority of this request.
   */
  uint32_t priority;

};


/**
 * A connected peer.
 */
struct GSF_ConnectedPeer 
{

  /**
   * Performance data for this peer.
   */
  struct GSF_PeerPerformanceData ppd;

  /**
   * Time until when we blocked this peer from migrating
   * data to us.
   */
  struct GNUNET_TIME_Absolute last_migration_block;

  /**
   * Messages (replies, queries, content migration) we would like to
   * send to this peer in the near future.  Sorted by priority, head.
   */
  struct GSF_PeerTransmitHandle *pth_head;

  /**
   * Messages (replies, queries, content migration) we would like to
   * send to this peer in the near future.  Sorted by priority, tail.
   */
  struct GSF_PeerTransmitHandle *pth_tail;

  /**
   * Migration stop message in our queue, or NULL if we have none pending.
   */
  struct GSF_PeerTransmitHandle *migration_pth;

  /**
   * Context of our GNUNET_CORE_peer_change_preference call (or NULL).
   * NULL if we have successfully reserved 32k, otherwise non-NULL.
   */
  struct GNUNET_CORE_InformationRequestContext *irc;

  /**
   * Active requests from this neighbour.
   */
  struct GNUNET_CONTAINER_MulitHashMap *request_map;

  /**
   * ID of delay task for scheduling transmission.
   */
  GNUNET_SCHEDULER_TaskIdentifier delayed_transmission_request_task; // FIXME: used in 'push' (ugh!)

  /**
   * Increase in traffic preference still to be submitted
   * to the core service for this peer.
   */
  uint64_t inc_preference;

  /**
   * Trust rating for this peer on disk.
   */
  uint32_t disk_trust;

  /**
   * The peer's identity.
   */
  GNUNET_PEER_Id pid;

  /**
   * Which offset in "last_p2p_replies" will be updated next?
   * (we go round-robin).
   */
  unsigned int last_p2p_replies_woff;

  /**
   * Which offset in "last_client_replies" will be updated next?
   * (we go round-robin).
   */
  unsigned int last_client_replies_woff;

  /**
   * Current offset into 'last_request_times' ring buffer.
   */
  unsigned int last_request_times_off;

};


/**
 * Map from peer identities to 'struct GSF_ConnectPeer' entries.
 */
static struct GNUNET_CONTAINER_MultiHashMap *cp_map;


/**
 * Where do we store trust information?
 */
static char *trustDirectory;


/**
 * Get the filename under which we would store the GNUNET_HELLO_Message
 * for the given host and protocol.
 * @return filename of the form DIRECTORY/HOSTID
 */
static char *
get_trust_filename (const struct GNUNET_PeerIdentity *id)
{
  struct GNUNET_CRYPTO_HashAsciiEncoded fil;
  char *fn;

  GNUNET_CRYPTO_hash_to_enc (&id->hashPubKey, &fil);
  GNUNET_asprintf (&fn, "%s%s%s", trustDirectory, DIR_SEPARATOR_STR, &fil);
  return fn;
}


/**
 * Find latency information in 'atsi'.
 *
 * @param atsi performance data
 * @return connection latency
 */
static struct GNUNET_TIME_Relative
get_latency (const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  if (atsi == NULL)
    return GNUNET_TIME_UNIT_SECONDS;
  while ( (ntohl (atsi->type) != GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR) &&
	  (ntohl (atsi->type) != GNUNET_TRANSPORT_ATS_QUALITY_NET_DELAY) )
    atsi++;
  if (ntohl (atsi->type) == GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR) 
    {
      GNUNET_break (0);
      /* how can we not have latency data? */
      return GNUNET_TIME_UNIT_SECONDS;
    }
  return GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS,
					ntohl (atsi->value));
}


/**
 * Update the performance information kept for the given peer.
 *
 * @param cp peer record to update
 * @param atsi transport performance data
 */
static void
update_atsi (struct GSF_ConnectedPeer *cp,
	     const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  struct GNUNET_TIME_Relative latency;

  latency = get_latency (atsi);
  GNUNET_LOAD_value_set_decline (cp->transmission_delay,
				 latency);
  /* LATER: merge atsi into cp's performance data (if we ever care...) */
}


/**
 * Return the performance data record for the given peer
 * 
 * @param cp peer to query
 * @return performance data record for the peer
 */
struct GSF_PeerPerformanceData *
GSF_get_peer_performance_data_ (struct GSF_ConnectedPeer *cp)
{
  return &cp->ppd;
}


/**
 * Core is ready to transmit to a peer, get the message.
 *
 * @param cls the 'struct GSF_PeerTransmitHandle' of the message
 * @param size number of bytes core is willing to take
 * @param buf where to copy the message
 * @return number of bytes copied to buf
 */
static size_t
peer_transmit_ready_cb (void *cls,
			size_t size,
			void *buf)
{
  struct GSF_PeerTransmitHandle *pth = cls;
  struct GSF_ConnectedPeer *cp;
  size_t ret;

  if (pth->timeout_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (pth->timeout_task);
      pth->timeout_task = GNUNET_SCHEDULER_NO_TASK;
    }
  cp = pth->cp;
  GNUNET_CONTAINER_DLL_remove (cp->pth_head,
			       cp->pth_tail,
			       pth);
  if (GNUNET_YES == pth->is_query)
    {
      cp->ppd.last_request_times[(cp->last_request_times_off++) % MAX_QUEUE_PER_PEER] = GNUNET_TIME_absolute_get ();
      GNUNET_assert (0 < cp->ppd.pending_queries--);    
    }
  else if (GNUNET_NO == pth->is_query)
    {
      GNUNET_assert (0 < cp->ppd.pending_replies--);
    }
  GNUNET_LOAD_update (cp->ppd.transmission_delay,
		      GNUNET_TIME_absolute_get_duration (pth->request_start_time).rel_value);  
  ret = pth->gmc (pth->gmc_cls, 
		  0, NULL);
  GNUNET_free (pth);  
  return ret;
}


/**
 * Function called by core upon success or failure of our bandwidth reservation request.
 *
 * @param cls the 'struct GSF_ConnectedPeer' of the peer for which we made the request
 * @param peer identifies the peer
 * @param bandwidth_out available amount of outbound bandwidth
 * @param amount set to the amount that was actually reserved or unreserved;
 *               either the full requested amount or zero (no partial reservations)
 * @param preference current traffic preference for the given peer
 */
static void
core_reserve_callback (void *cls,
		       const struct GNUNET_PeerIdentity * peer,
		       struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
		       int amount,
		       uint64_t preference)
{
  struct GSF_ConnectedPeer *cp = cls;
  uint64_t ip;

  cp->irc = NULL;
  if (0 == amount)
    {
      /* failed; retry! (how did we get here!?) */
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Failed to reserve bandwidth to peer `%s'\n"),
		  GNUNET_i2s (peer));
      ip = cp->inc_preference;
      cp->inc_preference = 0;
      cp->irc = GNUNET_CORE_peer_change_preference (core,
						    peer,
						    GNUNET_TIME_UNIT_FOREVER_REL,
						    GNUNET_BANDWIDTH_VALUE_MAX,
						    GNUNET_FS_DBLOCK_SIZE,
						    ip,
						    &core_reserve_callback,
						    cp);
      return;
    }
  pth = cp->pth_head;
  if ( (NULL != pth) &&
       (NULL == pth->cth) )
    {
      /* reservation success, try transmission now! */
      pth->cth = GNUNET_CORE_notify_transmit_ready (core,
						    priority,
						    GNUNET_TIME_absolute_get_remaining (pth->timeout),
						    &target,
						    size,
						    &peer_transmit_ready_cb,
						    pth);
    }
}


/**
 * A peer connected to us.  Setup the connected peer
 * records.
 *
 * @param peer identity of peer that connected
 * @param atsi performance data for the connection
 * @return handle to connected peer entry
 */
struct GSF_ConnectedPeer *
GSF_peer_connect_handler_ (const struct GNUNET_PeerIdentity *peer,
			   const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  struct GSF_ConnectedPeer *cp;
  char *fn;
  uint32_t trust;
  struct GNUNET_TIME_Relative latency;

  cp = GNUNET_malloc (sizeof (struct GSF_ConnectedPeer));
  cp->transmission_delay = GNUNET_LOAD_value_init (latency);
  cp->pid = GNUNET_PEER_intern (peer);
  cp->transmission_delay = GNUNET_LOAD_value_init (0);
  cp->irc = GNUNET_CORE_peer_change_preference (core,
						peer,
						GNUNET_TIME_UNIT_FOREVER_REL,
						GNUNET_BANDWIDTH_VALUE_MAX,
						GNUNET_FS_DBLOCK_SIZE,
						0,
						&core_reserve_callback,
						cp);
  fn = get_trust_filename (peer);
  if ((GNUNET_DISK_file_test (fn) == GNUNET_YES) &&
      (sizeof (trust) == GNUNET_DISK_fn_read (fn, &trust, sizeof (trust))))
    cp->disk_trust = cp->trust = ntohl (trust);
  GNUNET_free (fn);
  cp->request_map = GNUNET_CONTAINER_multihashmap_create (128);
  GNUNET_break (GNUNET_OK ==
		GNUNET_CONTAINER_multihashmap_put (cp_map,
						   &peer->hashPubKey,
						   cp,
						   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  update_atsi (cp, atsi);
  GSF_plan_notify_new_peer_ (cp);
  return cp;
}


/**
 * Handle P2P "MIGRATION_STOP" message.
 *
 * @param cls closure, always NULL
 * @param other the other peer involved (sender or receiver, NULL
 *        for loopback messages where we are both sender and receiver)
 * @param message the actual message
 * @param atsi performance information
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GSF_handle_p2p_migration_stop_ (void *cls,
				const struct GNUNET_PeerIdentity *other,
				const struct GNUNET_MessageHeader *message,
				const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  struct GSF_ConnectedPeer *cp; 
  const struct MigrationStopMessage *msm;

  msm = (const struct MigrationStopMessage*) message;
  cp = GNUNET_CONTAINER_multihashmap_get (cp_map,
					  &other->hashPubKey);
  if (cp == NULL)
    {
      GNUNET_break (0);
      return GNUNET_OK;
    }
  cp->ppd.migration_blocked_until = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_relative_ntoh (msm->duration));
  update_atsi (cp, atsi);
  return GNUNET_OK;
}


/**
 * Copy reply and free put message.
 *
 * @param cls the 'struct PutMessage'
 * @param buf_size number of bytes available in buf
 * @param buf where to copy the message, NULL on error (peer disconnect)
 * @return number of bytes copied to 'buf', can be 0 (without indicating an error)
 */
static size_t 
copy_reply (void *cls,
	    size_t buf_size,
	    void *buf)
{
  struct PutMessage *pm = cls;

  if (buf != NULL)
    {
      GNUNET_assert (size >= ntohs (pm->header.size));
      size = ntohs (pm->header.size);
      memcpy (buf, pm, size); 
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# replies transmitted to other peers"),
				1,
				GNUNET_NO); 
    }
  else
    {
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# replies dropped"),
				1,
				GNUNET_NO); 
    }
  GNUNET_free (pm);
  return size;
}


/**
 * Handle a reply to a pending request.  Also called if a request
 * expires (then with data == NULL).  The handler may be called
 * many times (depending on the request type), but will not be
 * called during or after a call to GSF_pending_request_cancel 
 * and will also not be called anymore after a call signalling
 * expiration.
 *
 * @param cls 'struct GSF_ConnectedPeer' of the peer that would
 *            have liked an answer to the request
 * @param pr handle to the original pending request
 * @param expiration when does 'data' expire?
 * @param data response data, NULL on request expiration
 * @param data_len number of bytes in data
 * @param more GNUNET_YES if the request remains active (may call
 *             this function again), GNUNET_NO if the request is
 *             finished (client must not call GSF_pending_request_cancel_)
 */
static void
handle_p2p_reply (void *cls,
		  struct GSF_PendingRequest *pr,
		  struct GNUNET_TIME_Absolute expiration,
		  const void *data,
		  size_t data_len,
		  int more)
{
  struct GSF_ConnectedPeer *cp = cls;
  struct GSF_PendingRequest *prd;
  struct PutMessage *pm;
  size_t msize;

  prd = GSF_pending_request_get_data_ (pr);
  if (NULL == data)
    {
      GNUNET_assert (GNUNET_NO == more);
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# P2P searches active"),
				-1,
				GNUNET_NO);
      GNUNET_break (GNUNET_OK ==
		    GNUNET_CONTAINER_multihashmap_remove (cp->request_map,
							  &prd->query,
							  pr));
      return;
    }
#if DEBUG_FS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Transmitting result for query `%s'\n",
	      GNUNET_h2s (key));
#endif  
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# replies received for other peers"),
			    1,
			    GNUNET_NO); 
  msize = sizeof (struct PutMessage) + data_len;
  pm = GNUNET_malloc (sizeof (msize));
  pm->header.type = htons (GNUNET_MESSAGE_TYPE_FS_PUT);
  pm->header.size = htons (msize);
  pm->type = htonl (prd->type);
  pm->expiration = GNUNET_TIME_absolute_hton (expiration);
  memcpy (&pm[1], data, data_len);
  (void) GSF_peer_transmit_ (cp, GNUNET_NO,
			     UINT32_MAX,
			     REPLY_TIMEOUT,
			     msize,
			     &copy_reply,
			     pm);
}


/**
 * Handle P2P "QUERY" message.  Creates the pending request entry
 * and sets up all of the data structures to that we will
 * process replies properly.  Does not initiate forwarding or
 * local database lookups.
 *
 * @param other the other peer involved (sender or receiver, NULL
 *        for loopback messages where we are both sender and receiver)
 * @param message the actual message
 * @return pending request handle, NULL on error
 */
struct GSF_PendingRequest *
GSF_handle_p2p_query_ (const struct GNUNET_PeerIdentity *other,
		       const struct GNUNET_MessageHeader *message)
{
  struct GSF_PendingRequest *pr;
  struct GSF_PendingRequestData *prd;
  struct GSF_ConnectedPeer *cp;
  struct GSF_ConnectedPeer *cps;
  GNUNET_HashCode *namespace;
  struct GNUNET_PeerIdentity *target;
  enum GSF_PendingRequestOptions options;			     
  struct GNUNET_TIME_Relative timeout;
  uint16_t msize;
  const struct GetMessage *gm;
  unsigned int bits;
  const GNUNET_HashCode *opt;
  uint32_t bm;
  size_t bfsize;
  uint32_t ttl_decrement;
  int32_t priority;
  int32_t ttl;
  enum GNUNET_BLOCK_Type type;


  msize = ntohs(message->size);
  if (msize < sizeof (struct GetMessage))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  gm = (const struct GetMessage*) message;
#if DEBUG_FS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received request for `%s'\n",
	      GNUNET_h2s (&gm->query));
#endif
  type = ntohl (gm->type);
  bm = ntohl (gm->hash_bitmap);
  bits = 0;
  while (bm > 0)
    {
      if (1 == (bm & 1))
	bits++;
      bm >>= 1;
    }
  if (msize < sizeof (struct GetMessage) + bits * sizeof (GNUNET_HashCode))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }  
  opt = (const GNUNET_HashCode*) &gm[1];
  bfsize = msize - sizeof (struct GetMessage) - bits * sizeof (GNUNET_HashCode);
  /* bfsize must be power of 2, check! */
  if (0 != ( (bfsize - 1) & bfsize))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  cover_query_count++;
  bm = ntohl (gm->hash_bitmap);
  bits = 0;
  cps = GNUNET_CONTAINER_multihashmap_get (connected_peers,
					   &other->hashPubKey);
  if (NULL == cps)
    {
      /* peer must have just disconnected */
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# requests dropped due to initiator not being connected"),
				1,
				GNUNET_NO);
      return GNUNET_SYSERR;
    }
  if (0 != (bm & GET_MESSAGE_BIT_RETURN_TO))
    cp = GNUNET_CONTAINER_multihashmap_get (connected_peers,
					    &opt[bits++]);
  else
    cp = cps;
  if (cp == NULL)
    {
#if DEBUG_FS
      if (0 != (bm & GET_MESSAGE_BIT_RETURN_TO))
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		    "Failed to find RETURN-TO peer `%4s' in connection set. Dropping query.\n",
		    GNUNET_i2s ((const struct GNUNET_PeerIdentity*) &opt[bits-1]));
      
      else
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		    "Failed to find peer `%4s' in connection set. Dropping query.\n",
		    GNUNET_i2s (other));
#endif
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# requests dropped due to missing reverse route"),
				1,
				GNUNET_NO);
      return GNUNET_OK;
    }
  /* note that we can really only check load here since otherwise
     peers could find out that we are overloaded by not being
     disconnected after sending us a malformed query... */
  priority = bound_priority (ntohl (gm->priority), cps);
  if (priority < 0)
    {
#if DEBUG_FS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Dropping query from `%s', this peer is too busy.\n",
		  GNUNET_i2s (other));
#endif
      return GNUNET_OK;
    }
#if DEBUG_FS 
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received request for `%s' of type %u from peer `%4s' with flags %u\n",
	      GNUNET_h2s (&gm->query),
	      (unsigned int) type,
	      GNUNET_i2s (other),
	      (unsigned int) bm);
#endif
  namespace = (0 != (bm & GET_MESSAGE_BIT_SKS_NAMESPACE)) ? &opt[bits++] : NULL;
  target = (0 != (bm & GET_MESSAGE_BIT_TRANSMIT_TO)) ? ((const struct GNUNET_PeerIdentity*) &opt[bits++]) : NULL;
  options = 0;
  if ( (GNUNET_LOAD_get_load (cp->transmission_delay) > 3 * (1 + priority)) ||
       (GNUNET_LOAD_get_average (cp->transmission_delay) > 
	GNUNET_CONSTANTS_MAX_CORK_DELAY.rel_value * 2 + GNUNET_LOAD_get_average (rt_entry_lifetime)) )
    {
      /* don't have BW to send to peer, or would likely take longer than we have for it,
	 so at best indirect the query */
      priority = 0;
      options |= GSF_PRO_FORWARD_ONLY;
    }
  ttl = bound_ttl (ntohl (gm->ttl), pr->priority);
  /* decrement ttl (always) */
  ttl_decrement = 2 * TTL_DECREMENT +
    GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
			      TTL_DECREMENT);
  if ( (ttl < 0) &&
       (((int32_t)(ttl - ttl_decrement)) > 0) )
    {
#if DEBUG_FS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Dropping query from `%s' due to TTL underflow (%d - %u).\n",
		  GNUNET_i2s (other),
		  ttl,
		  ttl_decrement);
#endif
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# requests dropped due TTL underflow"),
				1,
				GNUNET_NO);
      /* integer underflow => drop (should be very rare)! */      
      return GNUNET_OK;
    } 
  ttl -= ttl_decrement;

  /* test if the request already exists */
  pr = GNUNET_CONTAINER_multihashmap_get (cp->request_map,
					  &gm->query);
  if (pr != NULL) 
    {      
      prd = GSF_pending_request_get_data_ (pr);
      if ( (prd->type == type) &&
	   ( (type != GNUNET_BLOCK_TYPE_SBLOCK) ||
	     (0 == memcmp (prd->namespace,
			   namespace,
			   sizeof (GNUNET_HashCode))) ) )
	{
	  if (prd->ttl.abs_value >= GNUNET_TIME_absolute_get().abs_value + ttl)
	    {
	      /* existing request has higher TTL, drop new one! */
	      prd->priority += priority;
#if DEBUG_FS
	      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			  "Have existing request with higher TTL, dropping new request.\n",
			  GNUNET_i2s (other));
#endif
	      GNUNET_STATISTICS_update (stats,
					gettext_noop ("# requests dropped due to higher-TTL request"),
					1,
					GNUNET_NO);
	      return GNUNET_OK;
	    }
	  /* existing request has lower TTL, drop old one! */
	  pr->priority += prd->priority;
	  GSF_pending_request_cancel_ (pr);
	  GNUNET_assert (GNUNET_YES ==
			 GNUNET_CONTAINER_multihashmap_remove (cp->request_map,
							       &gm->query,
							       pr));
	}
    }
  
  pr = GSF_pending_request_create (options,
				   type,
				   &gm->query,
				   namespace,
				   target,
				   (bf_size > 0) ? (const char*)&opt[bits] : NULL,
				   bf_size,
				   ntohl (gm->filter_mutator),
				   1 /* anonymity */
				   (uint32_t) priority,
				   ttl,
				   NULL, 0, /* replies_seen */
				   &handle_p2p_reply,
				   cp);
  GNUNET_break (GNUNET_OK ==
		GNUNET_CONTAINER_multihashmap_put (cp->request_map,
						   &gm->query,
						   pr,
						   GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# P2P searches received"),
			    1,
			    GNUNET_NO);
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# P2P searches active"),
			    1,
			    GNUNET_NO);
  return pr;
}


/**
 * Function called if there has been a timeout trying to satisfy
 * a transmission request.
 *
 * @param cls the 'struct GSF_PeerTransmitHandle' of the request 
 * @param tc scheduler context
 */
static void
peer_transmit_timeout (void *cls,
		       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GSF_PeerTransmitHandle *pth = cls;
  struct GSF_ConnectedPeer *cp;
  
  pth->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  cp = pth->cp;
  GNUNET_CONTAINER_DLL_remove (cp->pth_head,
			       cp->pth_tail,
			       pth);
  if (GNUNET_YES == pth->is_query)
    GNUNET_assert (0 < cp->ppd.pending_queries--);    
  else if (GNUNET_NO == pth->is_query)
    GNUNET_assert (0 < cp->ppd.pending_replies--);
  GNUNET_LOAD_update (cp->ppd.transmission_delay,
		      UINT64_MAX);
  pth->gmc (pth->gmc_cls, 
	    0, NULL);
  GNUNET_free (pth);
}


/**
 * Transmit a message to the given peer as soon as possible.
 * If the peer disconnects before the transmission can happen,
 * the callback is invoked with a 'NULL' buffer.
 *
 * @param peer target peer
 * @param is_query is this a query (GNUNET_YES) or content (GNUNET_NO) or neither (GNUNET_SYSERR)
 * @param priority how important is this request?
 * @param timeout when does this request timeout (call gmc with error)
 * @param size number of bytes we would like to send to the peer
 * @param gmc function to call to get the message
 * @param gmc_cls closure for gmc
 * @return handle to cancel request
 */
struct GSF_PeerTransmitHandle *
GSF_peer_transmit_ (struct GSF_ConnectedPeer *peer,
		    int is_query,
		    uint32_t priority,
		    struct GNUNET_TIME_Relative timeout,
		    size_t size,
		    GSF_GetMessageCallback gmc,
		    void *gmc_cls)
{
  struct GSF_ConnectedPeer *cp;
  struct GSF_PeerTransmitHandle *pth;
  struct GSF_PeerTransmitHandle *pos;
  struct GSF_PeerTransmitHandle *prev;
  struct GNUNET_PeerIdentity target;
  uint64_t ip;
  int is_ready;

  cp = GNUNET_CONTAINER_multihashmap_get (cp_map,
					  &peer->hashPubKey);
  GNUNET_assert (NULL != cp);
  pth = GNUNET_malloc (sizeof (struct GSF_PeerTransmitHandle));
  pth->transmission_request_start_time = GNUNET_TIME_absolute_now ();
  pth->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  pth->gmc = gmc;
  pth->gmc_cls = gmc_cls;
  pth->size = size;
  pth->is_query = is_query;
  pth->priority = priority;
  pth->cp = cp;
  /* insertion sort (by priority, descending) */
  prev = NULL;
  pos = cp->pth_head;
  while ( (pos != NULL) &&
	  (pos->priority > priority) )
    {
      prev = pos;
      pos = pos->next;
    }
  if (prev == NULL)
    GNUNET_CONTAINER_DLL_insert_head (cp->pth_head,
				      cp->pth_tail,
				      pth);
  else
    GNUNET_CONTAINER_DLL_insert_after (cp->pth_head,
				       cp->pth_tail,
				       prev,
				       pth);
  GNUNET_PEER_resolve (cp->pid,
		       &target);
  if (GNUNET_YES == is_query)
    {
      /* query, need reservation */
      cp->ppd.pending_queries++;
      if (NULL == cp->irc)
	{
	  /* reservation already done! */
	  is_ready = GNUNET_YES;
	  ip = cp->inc_preference;
	  cp->inc_preference = 0;
	  cp->irc = GNUNET_CORE_peer_change_preference (core,
							peer,
							GNUNET_TIME_UNIT_FOREVER_REL,
							GNUNET_BANDWIDTH_VALUE_MAX,
							GNUNET_FS_DBLOCK_SIZE,
							ip,
							&core_reserve_callback,
							cp);	  
	}
      else
	{
	  /* still waiting for reservation */
	  is_ready = GNUNET_NO;
	}
    }
  else if (GNUNET_NO == is_query)
    {
      /* no reservation needed for content */
      cp->ppd.pending_replies++;
      is_ready = GNUNET_YES;
    }
  else
    {
      /* not a query or content, no reservation needed */
      is_ready = GNUNET_YES;
    }
  if (is_ready)
    {
      pth->cth = GNUNET_CORE_notify_transmit_ready (core,
						    priority,
						    timeout,
						    &target,
						    size,
						    &peer_transmit_ready_cb,
						    pth);
      /* pth->cth could be NULL here, that's OK, we'll try again
	 later... */
    }
  if (pth->cth == NULL)
    {
      /* if we're waiting for reservation OR if we could not do notify_transmit_ready,
	 install a timeout task to be on the safe side */
      pth->timeout_task = GNUNET_SCHEDULER_add_delayed (timeout,
							&peer_transmit_timeout,
							pth);
    }
  return pth;
}


/**
 * Cancel an earlier request for transmission.
 *
 * @param pth request to cancel
 */
void
GSF_peer_transmit_cancel_ (struct GSF_PeerTransmitHandle *pth)
{
  struct GSF_PeerTransmitHandle *pth = cls;
  struct GSF_ConnectedPeer *cp;

  if (pth->timeout_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (pth->timeout_task);
      pth->timeout_task = GNUNET_SCHEDULER_NO_TASK;
    }
  if (NULL != pth->cth)
    {
      GNUNET_CORE_notify_transmit_ready_cancel (pth->cth);
      pth->cth = NULL;
    }
  cp = pth->cp;
  GNUNET_CONTAINER_DLL_remove (cp->pth_head,
			       cp->pth_tail,
			       pth);
  if (GNUNET_YES == pth->is_query)
    GNUNET_assert (0 < cp->ppd.pending_queries--);    
  else if (GNUNET_NO == pth->is_query)
    GNUNET_assert (0 < cp->ppd.pending_replies--);
  GNUNET_free (pth);
}


/**
 * Report on receiving a reply; update the performance record of the given peer.
 *
 * @param cp responding peer (will be updated)
 * @param request_time time at which the original query was transmitted
 * @param request_priority priority of the original request
 */
void
GSF_peer_update_performance_ (struct GSF_ConnectedPeer *cp,
			      struct GNUNET_TIME_Absolute request_time,
			      uint32_t request_priority)
{
  struct GNUNET_TIME_Relative delay;

  delay = GNUNET_TIME_absolute_get_duration (request_time);  
  cp->ppd.avg_reply_delay = (cp->ppd.avg_reply_delay * (RUNAVG_DELAY_N-1) + delay.rel_value) / RUNAVG_DELAY_N;
  cp->ppd.avg_priority = (cp->avg_priority * (RUNAVG_DELAY_N-1) + request_priority) / RUNAVG_DELAY_N;
}


/**
 * Report on receiving a reply in response to an initiating client.
 * Remember that this peer is good for this client.
 *
 * @param cp responding peer (will be updated)
 * @param initiator_client local client on responsible for query
 */
void
GSF_peer_update_responder_client_ (struct GSF_ConnectedPeer *cp,
				   const struct GSF_LocalClient *initiator_client)
{
  cp->ppd.last_client_replies[cp->last_client_replies_woff++ % CS2P_SUCCESS_LIST_SIZE] = initiator_client;
}


/**
 * Report on receiving a reply in response to an initiating peer.
 * Remember that this peer is good for this initiating peer.
 *
 * @param cp responding peer (will be updated)
 * @param initiator_peer other peer responsible for query
 */
void
GSF_peer_update_responder_peer_ (struct GSF_ConnectedPeer *cp,
				 const struct GSF_ConnectedPeer *initiator_peer)
{
  GNUNET_PEER_change_rc (cp->ppd.last_p2p_replies[cp->last_p2p_replies_woff % P2P_SUCCESS_LIST_SIZE], -1);
  cp->ppd.last_p2p_replies[cp->last_p2p_replies_woff++ % P2P_SUCCESS_LIST_SIZE] = initiator_peer->pid;
  GNUNET_PEER_change_rc (initiator_peer->pid, 1);
}


/**
 * Method called whenever a given peer has a status change.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param bandwidth_in available amount of inbound bandwidth
 * @param bandwidth_out available amount of outbound bandwidth
 * @param timeout absolute time when this peer will time out
 *        unless we see some further activity from it
 * @param atsi status information
 */
void
GSF_peer_status_handler_ (void *cls,
			  const struct GNUNET_PeerIdentity *peer,
			  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
			  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
			  struct GNUNET_TIME_Absolute timeout,
			  const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  struct GSF_ConnectedPeer *cp;

  cp = GNUNET_CONTAINER_multihashmap_get (cp_map,
					  &peer->hashPubKey);
  GNUNET_assert (NULL != cp);
  update_atsi (cp, atsi);
}


/**
 * Cancel all requests associated with the peer.
 *
 * @param cls unused
 * @param query hash code of the request
 * @param value the 'struct GSF_PendingRequest'
 * @return GNUNET_YES (continue to iterate)
 */
static int
cancel_pending_request (void *cls,
			const GNUNET_HashCode *query,
			void *value)
{
  struct GSF_PendingRequest *pr = value;

  GSF_pending_request_cancel_ (pr);
  return GNUNET_OK;
}


/**
 * A peer disconnected from us.  Tear down the connected peer
 * record.
 *
 * @param cls unused
 * @param peer identity of peer that connected
 */
void
GSF_peer_disconnect_handler_ (void *cls,
			      const struct GNUNET_PeerIdentity *peer)
{
  struct GSF_ConnectedPeer *cp;
  struct GSF_PeerTransmitHandle *pth;

  cp = GNUNET_CONTAINER_multihashmap_get (cp_map,
					  &peer->hashPubKey);
  GNUNET_assert (NULL != cp);
  GNUNET_CONTAINER_multihashmap_remove (cp_map,
					&peer->hashPubKey,
					cp);
  if (NULL != cp->migration_pth)
    {
      GSF_peer_transmit_cancel_ (cp->migration_pth);
      cp->migration_pth = NULL;
    }
  if (NULL != cp->irc)
    {
      GNUNET_CORE_peer_change_preference_cancel (cp->irc);
      cp->irc = NULL;
    }
  GNUNET_CONTAINER_multihashmap_iterate (cp->request_map,
					 &cancel_pending_request,
					 cp);
  GNUNET_CONTAINER_multihashmap_destroy (cp->request_map);
  cp->request_map = NULL;
  GSF_plan_notify_peer_disconnect_ (cp);
  GNUNET_LOAD_value_free (cp->ppd.transmission_delay);
  GNUNET_PEER_decrement_rcs (cp->ppd.last_p2p_replies, P2P_SUCCESS_LIST_SIZE);
  while (NULL != (pth = cp->pth_head))
    {
      if (NULL != pth->th)
	{
	  GNUNET_CORE_notify_transmit_ready_cancel (pth->th);
	  pth->th = NULL;
	}
      GNUNET_CONTAINER_DLL_remove (cp->pth_head,
				   cp->pth_tail,
				   pth);
      GNUNET_free (pth);
    }
  GNUNET_PEER_change_rc (cp->pid, -1);
  GNUNET_free (cp);
}


/**
 * Closure for 'call_iterator'.
 */
struct IterationContext
{
  /**
   * Function to call on each entry.
   */
  GSF_ConnectedPeerIterator it;

  /**
   * Closure for 'it'.
   */
  void *it_cls;
};


/**
 * Function that calls the callback for each peer.
 *
 * @param cls the 'struct IterationContext*'
 * @param key identity of the peer
 * @param value the 'struct GSF_ConnectedPeer*'
 * @return GNUNET_YES to continue iteration
 */
static int
call_iterator (void *cls,
	       const GNUNET_HashCode *key,
	       void *value)
{
  struct IterationContext *ic = cls;
  struct GSF_ConnectedPeer *cp = value;
  
  ic->it (ic->it_cls,
	  (const struct GNUNET_PeerIdentity*) key,
	  cp,
	  &cp->ppd);
  return GNUNET_YES;
}


/**
 * Iterate over all connected peers.
 *
 * @param it function to call for each peer
 * @param it_cls closure for it
 */
void
GSF_iterate_connected_peers_ (GSF_ConnectedPeerIterator it,
			      void *it_cls)
{
  struct IterationContext ic;

  ic.it = it;
  ic.it_cls = it_cls;
  GNUNET_CONTAINER_multihashmap_iterate (cp_map,
					 &call_iterator,
					 &ic);
}


/**
 * Obtain the identity of a connected peer.
 *
 * @param cp peer to reserve bandwidth from
 * @param id identity to set (written to)
 */
void
GSF_connected_peer_get_identity_ (const struct GSF_ConnectedPeer *cp,
				  struct GNUNET_PeerIdentity *id)
{
  GNUNET_PEER_resolve (cp->pid,
		       &id);
}


/**
 * Assemble a migration stop message for transmission.
 *
 * @param cls the 'struct GSF_ConnectedPeer' to use
 * @param size number of bytes we're allowed to write to buf
 * @param buf where to copy the message
 * @return number of bytes copied to buf
 */
static size_t
create_migration_stop_message (void *cls,
			       size_t size,
			       void *buf)
{
  struct GSF_ConnectedPeer *cp = cls;
  struct MigrationStopMessage msm;

  cp->migration_pth = NULL;
  if (NULL == buf)
    return 0;
  GNUNET_assert (size > sizeof (struct MigrationStopMessage));
  msm.header.size = htons (sizeof (struct MigrationStopMessage));
  msm.header.type = htons (GNUNET_MESSAGE_TYPE_FS_MIGRATION_STOP);
  msm.duration = GNUNET_TIME_relative_hton (GNUNET_TIME_absolute_get_remaining (cp->last_migration_block));
  memcpy (buf, &msm, sizeof (struct MigrationStopMessage));
  return sizeof (struct MigrationStopMessage);
}


/**
 * Ask a peer to stop migrating data to us until the given point
 * in time.
 * 
 * @param cp peer to ask
 * @param block_time until when to block
 */
void
GSF_block_peer_migration_ (struct GSF_ConnectedPeer *cp,
			   struct GNUNET_TIME_Relative block_time)
{
  if (GNUNET_TIME_absolute_get_duration (cp->last_migration_block).rel_value > block_time.rel_value)
    return; /* already blocked */
  cp->last_migration_block = GNUNET_TIME_relative_to_absolute (block_time);
  if (cp->migration_pth != NULL)
    GSF_peer_transmit_cancel_ (cp->migration_pth);
  cp->migration_pth 
    = GSF_peer_transmit_ (cp,
			  GNUNET_SYSERR,
			  UINT32_MAX,
			  GNUNET_TIME_UNIT_FOREVER_REL,
			  sizeof (struct MigrationStopMessage),
			  &create_migration_stop_message,
			  cp);
}


/**
 * Write host-trust information to a file - flush the buffer entry!
 *
 * @param cls closure, not used
 * @param key host identity
 * @param value the 'struct GSF_ConnectedPeer' to flush
 * @return GNUNET_OK to continue iteration
 */
static int
flush_trust (void *cls,
	     const GNUNET_HashCode *key,
	     void *value)
{
  struct GSF_ConnectedPeer *cp = value;
  char *fn;
  uint32_t trust;
  struct GNUNET_PeerIdentity pid;

  if (cp->trust == cp->disk_trust)
    return GNUNET_OK;                     /* unchanged */
  GNUNET_PEER_resolve (cp->pid,
		       &pid);
  fn = get_trust_filename (&pid);
  if (cp->trust == 0)
    {
      if ((0 != UNLINK (fn)) && (errno != ENOENT))
        GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING |
                                  GNUNET_ERROR_TYPE_BULK, "unlink", fn);
    }
  else
    {
      trust = htonl (cp->trust);
      if (sizeof(uint32_t) == GNUNET_DISK_fn_write (fn, &trust, 
						    sizeof(uint32_t),
						    GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE
						    | GNUNET_DISK_PERM_GROUP_READ | GNUNET_DISK_PERM_OTHER_READ))
        cp->disk_trust = cp->trust;
    }
  GNUNET_free (fn);
  return GNUNET_OK;
}


/**
 * Notify core about a preference we have for the given peer
 * (to allocate more resources towards it).  The change will
 * be communicated the next time we reserve bandwidth with
 * core (not instantly).
 *
 * @param cp peer to reserve bandwidth from
 * @param pref preference change
 */
void
GSF_connected_peer_change_preference_ (struct GSF_ConnectedPeer *cp,
				       uint64_t pref)
{
  cp->inc_preference += pref;
}


/**
 * Call this method periodically to flush trust information to disk.
 *
 * @param cls closure, not used
 * @param tc task context, not used
 */
static void
cron_flush_trust (void *cls,
		  const struct GNUNET_SCHEDULER_TaskContext *tc)
{

  if (NULL == cp_map)
    return;
  GNUNET_CONTAINER_multihashmap_iterate (cp_map,
					 &flush_trust,
					 NULL);
  if (NULL == tc)
    return;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  GNUNET_SCHEDULER_add_delayed (TRUST_FLUSH_FREQ, 
				&cron_flush_trust, 
				NULL);
}


/**
 * Initialize peer management subsystem.
 *
 * @param cfg configuration to use
 */
void
GSF_connected_peer_init_ (struct GNUNET_CONFIGURATION_Handle *cfg)
{
  cp_map = GNUNET_CONTAINER_multihashmap_create (128);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_filename (cfg,
                                                          "fs",
                                                          "TRUST",
                                                          &trustDirectory));
  GNUNET_DISK_directory_create (trustDirectory);
  GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_HIGH,
				      &cron_flush_trust, NULL);
}


/**
 * Iterator to free peer entries.
 *
 * @param cls closure, unused
 * @param key current key code
 * @param value value in the hash map (peer entry)
 * @return GNUNET_YES (we should continue to iterate)
 */
static int 
clean_peer (void *cls,
	    const GNUNET_HashCode * key,
	    void *value)
{
  GSF_peer_disconnect_handler_ (NULL, 
				(const struct GNUNET_PeerIdentity*) key);
  return GNUNET_YES;
}


/**
 * Shutdown peer management subsystem.
 */
void
GSF_connected_peer_done_ ()
{
  cron_flush_trust (NULL, NULL);
  GNUNET_CONTAINER_multihashmap_iterate (cp_map,
					 &clean_peer,
					 NULL);
  GNUNET_CONTAINER_multihashmap_destroy (cp_map);
  cp_map = NULL;
  GNUNET_free (trustDirectory);
  trustDirectory = NULL;
}


/**
 * Iterator to remove references to LC entry.
 *
 * @param the 'struct GSF_LocalClient*' to look for
 * @param key current key code
 * @param value value in the hash map (peer entry)
 * @return GNUNET_YES (we should continue to iterate)
 */
static int 
clean_local_client (void *cls,
		    const GNUNET_HashCode * key,
		    void *value)
{
  const struct GSF_LocalClient *lc = cls;
  struct GSF_ConnectedPeer *cp = value;
  unsigned int i;

  for (i=0;i<CS2P_SUCCESS_LIST_SIZE;i++)
    if (cp->ppd.last_client_replies[i] == lc)
      cp->ppd.last_client_replies[i] = NULL;
  return GNUNET_YES;
}


/**
 * Notification that a local client disconnected.  Clean up all of our
 * references to the given handle.
 *
 * @param lc handle to the local client (henceforth invalid)
 */
void
GSF_handle_local_client_disconnect_ (const struct GSF_LocalClient *lc)
{
  GNUNET_CONTAINER_multihashmap_iterate (cp_map,
					 &clean_local_client,
					 (void*) lc);
}


/* end of gnunet-service-fs_cp.c */
