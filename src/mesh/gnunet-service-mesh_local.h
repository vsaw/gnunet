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
 * @file mesh/gnunet-service-mesh_local.h
 * @brief mesh service; dealing with local clients
 * @author Bartlomiej Polot
 *
 * All functions in this file should use the prefix GML (Gnunet Mesh Local)
 */

#ifndef GNUNET_SERVICE_MESH_LOCAL_H
#define GNUNET_SERVICE_MESH_LOCAL_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "platform.h"
#include "gnunet_util_lib.h"

#include "gnunet-service-mesh_channel.h"

/**
 * Struct containing information about a client of the service
 */
struct MeshClient;

/******************************************************************************/
/********************************    API    ***********************************/
/******************************************************************************/

/**
 * Initialize server subsystem.
 *
 * @param handle Server handle.
 */
void
GML_init (struct GNUNET_SERVER_Handle *handle);

/**
 * Install server (service) handlers and start listening to clients.
 */
void
GML_start (void);

/**
 * Shutdown server.
 */
void
GML_shutdown (void);

/**
 * Check if client has registered with the service and has not disconnected
 *
 * @param client the client to check
 *
 * @return non-NULL if client exists in the global DLL
 */
struct MeshClient *
GML_client_get (struct GNUNET_SERVER_Client *client);

/**
 * Deletes a tunnel from a client (either owner or destination).
 *
 * @param c Client whose tunnel to delete.
 * @param ch Channel which should be deleted.
 */
void
GML_client_delete_channel (struct MeshClient *c, struct MeshChannel *ch);

/**
 * Build a local ACK message and send it to a local client, if needed.
 *
 * If the client was already allowed to send data, do nothing.
 *
 * @param ch Channel on which to send the ACK.
 * @param c Client to whom send the ACK.
 * @param fwd Set to GNUNET_YES for FWD ACK (dest->root)
 */
void
GML_send_ack (struct MeshChannel *ch, int fwd);

/**
 * Notify the appropriate client that a new incoming channel was created.
 *
 * @param ch Channel that was created.
 */
void
GML_send_channel_create (struct MeshClient *c,
                         uint32_t id, uint32_t port, uint32_t opt,
                         struct GNUNET_PeerIdentity *peer);

/**
 * Notify a client that a channel is no longer valid.
 *
 * @param c Client.
 * @param id ID of the channel that is destroyed.
 */
void
GML_send_channel_destroy (struct MeshClient *c, uint32_t id);

/**
 * Modify the mesh message TID from global to local and send to client.
 *
 * @param ch Channel on which to send the message.
 * @param msg Message to modify and send.
 * @param c Client to send to.
 * @param tid Tunnel ID to use (c can be both owner and client).
 */
void
GML_send_data (struct MeshChannel *ch,
               const struct GNUNET_MESH_Data *msg,
               struct MeshClient *c, MESH_ChannelNumber id);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_MESH_SERVICE_LOCAL_H */
#endif
/* end of gnunet-mesh-service_LOCAL.h */