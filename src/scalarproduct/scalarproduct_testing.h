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
 * @file scalarproduct/scalarproduct_testing.h
 * @brief VectorProduct testcase common declarations
 * @author Gaurav Kukreja
 * @author Christian Fuchs
 *
 * Created on June 29, 2013, 7:39 PM
 */

#ifndef SCALARPRODUCT_TESTING_H
#define	SCALARPRODUCT_TESTING_H

#ifdef	__cplusplus
extern "C" {
#endif

struct GNUNET_SCALARPRODUCT_TESTING_handle
{
  /**
   * Testing library system handle
   */
  struct GNUNET_TESTING_System *tl_system;

  /**
   * head DLL of peers
   */
  struct PeerContext *p_head;

  /**
   * tail DLL of peers
   */
  struct PeerContext *p_tail;
};

struct PeerContext
{
  /**
   * Next element in the DLL
   */
  struct PeerContext *next;

  /**
   * Previous element in the DLL
   */
  struct PeerContext *prev;

  /**
   * Peer's testing handle
   */
  struct GNUNET_TESTING_Peer *peer;

  /**
   * Peer identity
   */
  struct GNUNET_PeerIdentity id;

  /**
   * Handle for the peer's ARM process
   */
  struct GNUNET_OS_Process *arm_proc;

  /**
   * Pointer to Vector Product Handle
   */
  struct GNUNET_SCALARPRODUCT_Handle *vh;

  /**
   * Closure for the callbacks
   */
  void *cb_cls;

  /**
   * An unique number to identify the peer
   */
  unsigned int no;

  /**
   * Peer's configuration
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Pointer to the master testing handle
   */
  struct GNUNET_SCALARPRODUCT_TESTING_handle * vth;

  /**
    * Callback when two peers are connected and both have called the connect callback
    * to notify clients about a new peer
    */
   void (*start_cb) (struct PeerContext * p, void *cls);

//  /**
//   * Pointer to function where the test occurs
//   */
//  GNUNET_SCALARPRODUCT_TESTING_start_cb start_cb;
};

/**
 * Callback when two peers are connected and both have called the connect callback
 * to notify clients about a new peer
 */
typedef void (*GNUNET_SCALARPRODUCT_TESTING_start_cb) (struct PeerContext * p,
                                                   void *cls);

struct GNUNET_SCALARPRODUCT_TESTING_handle *
GNUNET_SCALARPRODUCT_TESTING_init();

static void
GNUNET_SCALARPRODUCT_TESTING_done(struct GNUNET_SCALARPRODUCT_TESTING_handle * vth);

struct PeerContext *
GNUNET_SCALARPRODUCT_TESTING_start_peer (struct GNUNET_SCALARPRODUCT_TESTING_handle * vth,
                                     const char *cfgname, int peer_id,
                                     GNUNET_SCALARPRODUCT_TESTING_start_cb start_cb,
                                     void *cb_cls);

static void
GNUNET_SCALARPRODUCT_TESTING_stop_peer
        (struct GNUNET_SCALARPRODUCT_TESTING_handle * vth,
        struct PeerContext *p);




#ifdef	__cplusplus
}
#endif

#endif	/* SCALARPRODUCT_TESTING_H */

