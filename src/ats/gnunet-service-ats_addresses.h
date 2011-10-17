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
 * @file ats/gnunet-service-ats_addresses.c
 * @brief ats service address management
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_ATS_ADDRESSES_H
#define GNUNET_SERVICE_ATS_ADDRESSES_H

#include "gnunet_util_lib.h"
#include "gnunet_transport_service.h" // FIXME...
#include "gnunet_ats_service.h" 
#include "ats.h"

/**
 * Initialize address subsystem.
 * @param cfg configuration to use
 */
void
GAS_addresses_init (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Shutdown address subsystem.
 */
void
GAS_addresses_done (void);


void
GAS_address_update (const struct GNUNET_PeerIdentity *peer,
		    const char *plugin_name,
		    const void *plugin_addr, size_t plugin_addr_len,
		    struct GNUNET_SERVER_Client *session_client,
		    uint32_t session_id,
		    const struct GNUNET_TRANSPORT_ATS_Information *atsi,
		    uint32_t atsi_count);


void
GAS_address_destroyed (const struct GNUNET_PeerIdentity *peer,
		       const char *plugin_name,
		       const void *plugin_addr, size_t plugin_addr_len,
		       struct GNUNET_SERVER_Client *session_client,
		       uint32_t session_id);

void
GAS_address_client_disconnected (struct GNUNET_SERVER_Client *session_client);

// FIXME: this function should likely end up in the LP-subsystem and
// not with 'addresses' in the future...
// Note: this call should trigger an address suggestion
// (GAS_scheduling_transmit_address_suggestion)
void
GAS_addresses_request_address (const struct GNUNET_PeerIdentity *peer);


// FIXME: this function should likely end up in the LP-subsystem and
// not with 'addresses' in the future...
void
GAS_addresses_change_preference (const struct GNUNET_PeerIdentity *peer,
				 enum GNUNET_ATS_PreferenceKind kind,
				 float score);


/* FIXME: add performance request API */

#endif
