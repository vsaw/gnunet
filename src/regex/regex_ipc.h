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
 * @file regex/regex_ipc.h
 * @brief regex IPC messages (not called 'regex.h' due to conflict with
 *        system headers)
 * @author Christian Grothoff
 */
#ifndef REGEX_IPC_H
#define REGEX_IPC_H

#include "gnunet_util_lib.h"

/**
 * Request for regex service to announce capability.
 */
struct AnnounceMessage
{

  /**
   * Type is GNUNET_MESSAGE_TYPE_REGEX_ANNOUNCE
   */
  struct GNUNET_MessageHeader header;

  /**
   * How many characters can we squeeze per edge?
   */
  uint16_t compression;

  /**
   * Always zero.
   */
  uint16_t reserved;

  /**
   * The EdDSA key to sign announcements with.
   *
   * OPTIONAL If NULL the default key of the peer, as retrieved from the config
   * of GNUnet Service REGEX will be used.
   */
  struct GNUNET_CRYPTO_EddsaPrivateKey key;

  /**
   * Delay between repeated announcements.
   */
  struct GNUNET_TIME_RelativeNBO refresh_delay;

  /* followed by 0-terminated regex as string */
};


/**
 * Message to initiate regex search.
 */
struct RegexSearchMessage
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_REGEX_SEARCH
   */
  struct GNUNET_MessageHeader header;

  /* followed by 0-terminated search string */

};


/**
 * Result from regex search.
 */
struct ResultMessage
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_REGEX_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * The DHT key where the peer was found.
   */
  struct GNUNET_HashCode key;

  /**
   * Number of entries in the GET path.
   */
  uint16_t get_path_length;

  /**
   * Number of entries in the PUT path.
   */
  uint16_t put_path_length;

  /**
   * Identity of the peer that was found.
   */
  struct GNUNET_PeerIdentity id;

  /* followed by GET path and PUT path arrays */

};


/**
 * Request the accepting DHT-Keys for an Announcement
 */
struct DhtKeyRequestMessage
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_REGEX_GET_ACCEPTING_DHT_ENTRIES
   */
  struct GNUNET_MessageHeader header;

  /**
   * The original Announce message for which the accepting states need to be
   * looked up
   */
  struct AnnounceMessage original_announce;
};


/**
 * Response for accepting DHT-Keys
 */
struct DhtKeyResponseMessage
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_REGEX_ACCEPTING_DHT_ENTRIES
   */
  struct GNUNET_MessageHeader header;

  /**
   * The amount of accepting DHT keys
   */
  uint16_t num_entries;

  /* Followed by list of struct GNUNET_HashCode + 0-terminated proof
   * Essentially the list looks like this:
   *
   *     | hashCode0 | proof0 | hashCode1 | proof1 | ... | hashCodeN | proofN |
   *
   * Where each proof is a '\0'-terminated string of variable length. So there
   * is no direct way to access the i-th hashCode other than iterating through
   * the list.
   */
};


/* end of regex_ipc.h */
#endif
