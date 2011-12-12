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
#include "platform.h"
#include "gnunet_ats_service.h"
#include "gnunet-service-ats.h"
#include "gnunet-service-ats_addresses.h"
#include "gnunet-service-ats_performance.h"
#include "gnunet-service-ats_scheduling.h"
#include "gnunet-service-ats_reservations.h"

struct ATS_Address
{
  struct GNUNET_PeerIdentity peer;

  size_t addr_len;

  uint32_t session_id;

  uint32_t ats_count;

  const void *addr;

  char *plugin;

  struct GNUNET_ATS_Information *ats;

  struct GNUNET_TIME_Relative atsp_latency;

  struct GNUNET_BANDWIDTH_Value32NBO atsp_utilization_in;

  struct GNUNET_BANDWIDTH_Value32NBO atsp_utilization_out;

  uint32_t atsp_distance;

  uint32_t atsp_cost_wan;

  uint32_t atsp_cost_lan;

  uint32_t atsp_cost_wlan;

  struct GNUNET_BANDWIDTH_Value32NBO assigned_bw_in;

  struct GNUNET_BANDWIDTH_Value32NBO assigned_bw_out;

  /**
   * Is this the active address for this peer?
   */
  int active;

};

struct ATS_Network
{
  struct ATS_Network * next;

  struct ATS_Network * prev;

  struct sockaddr *network;
  struct sockaddr *netmask;
  socklen_t length;
};


struct ATS_Network * net_head;

struct ATS_Network * net_tail;

static struct GNUNET_CONTAINER_MultiHashMap *addresses;

static unsigned long long wan_quota_in;

static unsigned long long wan_quota_out;

static unsigned int active_addr_count;

static GNUNET_SCHEDULER_TaskIdentifier interface_task;


/**
 * Update a bandwidth assignment for a peer.  This trivial method currently
 * simply assigns the same share to all active connections.
 *
 * @param cls unused
 * @param key unused
 * @param value the 'struct ATS_Address'
 * @return GNUNET_OK (continue to iterate)
 */
static int
update_bw_it (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct ATS_Address *aa = value;

  if (GNUNET_YES != aa->active)
    return GNUNET_OK;
  GNUNET_assert (active_addr_count > 0);
  aa->assigned_bw_in.value__ = htonl (wan_quota_in / active_addr_count);
  aa->assigned_bw_out.value__ = htonl (wan_quota_out / active_addr_count);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "New bandwidth for peer %s is %u/%u\n",
              GNUNET_i2s (&aa->peer), ntohl (aa->assigned_bw_in.value__),
              ntohl (aa->assigned_bw_out.value__));
  GAS_scheduling_transmit_address_suggestion (&aa->peer, aa->plugin, aa->addr,
                                              aa->addr_len, aa->session_id,
                                              aa->ats, aa->ats_count,
                                              aa->assigned_bw_out,
                                              aa->assigned_bw_in);
  GAS_reservations_set_bandwidth (&aa->peer, aa->assigned_bw_in);
  GAS_performance_notify_clients (&aa->peer, aa->plugin, aa->addr, aa->addr_len,
                                  aa->ats, aa->ats_count, aa->assigned_bw_out,
                                  aa->assigned_bw_in);
  return GNUNET_OK;
}


/**
 * Some (significant) input changed, recalculate bandwidth assignment
 * for all peers.
 */
static void
recalculate_assigned_bw ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Recalculating bandwidth for all active connections\n");
  GNUNET_STATISTICS_update (GSA_stats, "# bandwidth recalculations performed",
                            1, GNUNET_NO);
  GNUNET_STATISTICS_set (GSA_stats, "# active addresses", active_addr_count,
                         GNUNET_NO);
  GNUNET_CONTAINER_multihashmap_iterate (addresses, &update_bw_it, NULL);
}


/**
 * Destroy the given address.
 *
 * @param addr address to destroy
 * @return GNUNET_YES if bandwidth allocations should be recalcualted
 */
static int
destroy_address (struct ATS_Address *addr)
{
  int ret;

  ret = GNUNET_NO;
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (addresses,
                                                       &addr->peer.hashPubKey,
                                                       addr));
  if (GNUNET_YES == addr->active)
  {
    active_addr_count--;
    addr->active = GNUNET_NO;
    ret = GNUNET_YES;
  }
  GNUNET_free_non_null (addr->ats);
  GNUNET_free (addr->plugin);
  GNUNET_free (addr);
  return ret;
}


struct CompareAddressContext
{
  const struct ATS_Address *search;
  struct ATS_Address *result;
};


static int
compare_address_it (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct CompareAddressContext *cac = cls;
  struct ATS_Address *aa = value;

  if (((aa->addr_len != cac->search->addr_len) ||
       (0 != strcmp (aa->plugin, cac->search->plugin)) ||
       (0 != memcmp (aa->addr, cac->search->addr, aa->addr_len))) &&
      ((aa->session_id != cac->search->session_id) ||
       (cac->search->session_id == 0)))
    return GNUNET_YES;
  cac->result = aa;
  return GNUNET_NO;
}


/**
 * Find an existing equivalent address record.
 * Compares by peer identity and network address OR by session ID
 * (one of the two must match).
 *
 * @param peer peer to lookup addresses for
 * @param addr existing address record
 * @return existing address record, NULL for none
 */
struct ATS_Address *
find_address (const struct GNUNET_PeerIdentity *peer,
              const struct ATS_Address *addr)
{
  struct CompareAddressContext cac;

  cac.result = NULL;
  cac.search = addr;
  GNUNET_CONTAINER_multihashmap_get_multiple (addresses, &peer->hashPubKey,
                                              &compare_address_it, &cac);
  return cac.result;
}


void
GAS_addresses_update (const struct GNUNET_PeerIdentity *peer,
                      const char *plugin_name, const void *plugin_addr,
                      size_t plugin_addr_len, uint32_t session_id,
                      const struct GNUNET_ATS_Information *atsi,
                      uint32_t atsi_count)
{
  struct ATS_Address *aa;
  struct ATS_Address *old;
  uint32_t i;

  aa = GNUNET_malloc (sizeof (struct ATS_Address) + plugin_addr_len);
  aa->ats = GNUNET_malloc (atsi_count * sizeof (struct GNUNET_ATS_Information));
  aa->peer = *peer;
  aa->addr_len = plugin_addr_len;
  aa->ats_count = atsi_count;
  memcpy (aa->ats, atsi, atsi_count * sizeof (struct GNUNET_ATS_Information));
  aa->addr = &aa[1];
  memcpy (&aa[1], plugin_addr, plugin_addr_len);
  aa->plugin = GNUNET_strdup (plugin_name);
  aa->session_id = session_id;
  old = find_address (peer, aa);
  if (old == NULL)
  {
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multihashmap_put (addresses,
                                                      &peer->hashPubKey, aa,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Added new address for peer `%s' %X\n",
                GNUNET_i2s (peer), aa);
    old = aa;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Updated existing address for peer `%s' %X \n",
                GNUNET_i2s (peer), old);
    GNUNET_free_non_null (old->ats);
    old->session_id = session_id;
    old->ats = NULL;
    old->ats_count = 0;
    old->ats = aa->ats;
    old->ats_count = aa->ats_count;
    GNUNET_free (aa->plugin);
    GNUNET_free (aa);
  }
  for (i = 0; i < atsi_count; i++)
    switch (ntohl (atsi[i].type))
    {
    case GNUNET_ATS_UTILIZATION_UP:
      old->atsp_utilization_out.value__ = atsi[i].value;
      break;
    case GNUNET_ATS_UTILIZATION_DOWN:
      old->atsp_utilization_in.value__ = atsi[i].value;
      break;
    case GNUNET_ATS_QUALITY_NET_DELAY:
      old->atsp_latency.rel_value = ntohl (atsi[i].value);
      break;
    case GNUNET_ATS_QUALITY_NET_DISTANCE:
      old->atsp_distance = ntohl (atsi[i].value);
      break;
    case GNUNET_ATS_COST_WAN:
      old->atsp_cost_wan = ntohl (atsi[i].value);
      break;
    case GNUNET_ATS_COST_LAN:
      old->atsp_cost_lan = ntohl (atsi[i].value);
      break;
    case GNUNET_ATS_COST_WLAN:
      old->atsp_cost_wlan = ntohl (atsi[i].value);
      break;
    default:
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Received unsupported ATS type %u\n", ntohl (atsi[i].type));
      GNUNET_break (0);
      break;
    }
}


/**
 * Update a bandwidth assignment for a peer.  This trivial method currently
 * simply assigns the same share to all active connections.
 *
 * @param cls unused
 * @param key unused
 * @param value the 'struct ATS_Address'
 * @return GNUNET_OK (continue to iterate)
 */
static int
destroy_by_session_id (void *cls, const GNUNET_HashCode * key, void *value)
{
  const struct ATS_Address *info = cls;
  struct ATS_Address *aa = value;

  GNUNET_assert (0 ==
                 memcmp (&aa->peer, &info->peer,
                         sizeof (struct GNUNET_PeerIdentity)));
  if ((info->session_id == 0) && (0 == strcmp (info->plugin, aa->plugin)) &&
      (aa->addr_len == info->addr_len) &&
      (0 == memcmp (info->addr, aa->addr, aa->addr_len)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Deleting address for peer `%s': `%s'\n",
                GNUNET_i2s (&aa->peer), aa->plugin);
    if (GNUNET_YES == destroy_address (aa))
      recalculate_assigned_bw ();
    return GNUNET_OK;
  }
  if (aa->session_id != info->session_id)
    return GNUNET_OK;           /* irrelevant */
  if (aa->session_id != 0)
    GNUNET_break (0 == strcmp (info->plugin, aa->plugin));
  /* session died */
  aa->session_id = 0;

  if (GNUNET_YES == aa->active)
  {
    aa->active = GNUNET_NO;
    active_addr_count--;
    recalculate_assigned_bw ();
  }

  /* session == 0 and addrlen == 0 : destroy address */
  if (aa->addr_len == 0)
    (void) destroy_address (aa);

  return GNUNET_OK;
}


void
GAS_addresses_destroy (const struct GNUNET_PeerIdentity *peer,
                       const char *plugin_name, const void *plugin_addr,
                       size_t plugin_addr_len, uint32_t session_id)
{
  struct ATS_Address aa;

  GNUNET_break (0 < strlen (plugin_name));
  aa.peer = *peer;
  aa.addr_len = plugin_addr_len;
  aa.addr = plugin_addr;
  aa.plugin = (char *) plugin_name;
  aa.session_id = session_id;
  GNUNET_CONTAINER_multihashmap_get_multiple (addresses, &peer->hashPubKey,
                                              &destroy_by_session_id, &aa);
}


/**
 * Find a "good" address to use for a peer.  If we already have an existing
 * address, we stick to it.  Otherwise, we pick by lowest distance and then
 * by lowest latency.
 *
 * @param cls the 'struct ATS_Address**' where we store the result
 * @param key unused
 * @param value another 'struct ATS_Address*' to consider using
 * @return GNUNET_OK (continue to iterate)
 */
static int
find_address_it (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct ATS_Address **ap = cls;
  struct ATS_Address *aa = (struct ATS_Address *) value;
  struct ATS_Address *ab = *ap;

  if (NULL == ab)
  {
    *ap = aa;
    return GNUNET_OK;
  }
  if ((ntohl (ab->assigned_bw_in.value__) == 0) &&
      (ntohl (aa->assigned_bw_in.value__) > 0))
  {
    /* stick to existing connection */
    *ap = aa;
    return GNUNET_OK;
  }
  if (ab->atsp_distance > aa->atsp_distance)
  {
    /* user shorter distance */
    *ap = aa;
    return GNUNET_OK;
  }
  if (ab->atsp_latency.rel_value > aa->atsp_latency.rel_value)
  {
    /* user lower latency */
    *ap = aa;
    return GNUNET_OK;
  }
  /* don't care */
  return GNUNET_OK;
}


void
GAS_addresses_in_use (const struct GNUNET_PeerIdentity *peer,
                      const char *plugin_name, const void *plugin_addr,
                      size_t plugin_addr_len, uint32_t session_id, int in_use)
{

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' message for peer `%s': %i\n", "ADDRESS_IN_USE",
              GNUNET_i2s (peer), in_use);
}

void
GAS_addresses_request_address (const struct GNUNET_PeerIdentity *peer)
{
  struct ATS_Address *aa;

  aa = NULL;
  GNUNET_CONTAINER_multihashmap_get_multiple (addresses, &peer->hashPubKey,
                                              &find_address_it, &aa);
  if (aa == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Cannot suggest address for peer `%s'\n", GNUNET_i2s (peer));
    return;
  }
  if (aa->active == GNUNET_NO)
  {
    aa->active = GNUNET_YES;
    active_addr_count++;
    recalculate_assigned_bw ();
  }
  else
  {
    /* just to be sure... */
    GAS_scheduling_transmit_address_suggestion (peer, aa->plugin, aa->addr,
                                                aa->addr_len, aa->session_id,
                                                aa->ats, aa->ats_count,
                                                aa->assigned_bw_out,
                                                aa->assigned_bw_in);
  }
}


// FIXME: this function should likely end up in the LP-subsystem and
// not with 'addresses' in the future...
void
GAS_addresses_change_preference (const struct GNUNET_PeerIdentity *peer,
                                 enum GNUNET_ATS_PreferenceKind kind,
                                 float score)
{
  // do nothing for now...
}

/**
 * Returns where the address is located: LAN or WAN or ...
 * @param addr address
 * @param addrlen address length
 * @return location as GNUNET_ATS_Information
 */

struct GNUNET_ATS_Information
GAS_addresses_type (const struct sockaddr * addr, socklen_t addrlen)
{
  struct GNUNET_ATS_Information ats;
  struct ATS_Network * cur = net_head;
  int type = GNUNET_ATS_NET_UNSPECIFIED;

  /* IPv4 loopback check */
  if  (addr->sa_family == AF_INET)
  {
    struct sockaddr_in * a4 = (struct sockaddr_in *) addr;

    if (((a4->sin_addr.s_addr & htonl(0xff000000)) & htonl (0x7f000000)) == htonl (0x7f000000))
      type = GNUNET_ATS_NET_LOOPBACK;
  }
  /* IPv6 loopback check */
  if  (addr->sa_family == AF_INET6)
  {
    struct sockaddr_in6 * a6 = (struct sockaddr_in6 *) addr;
    if (IN6_IS_ADDR_LOOPBACK (&a6->sin6_addr))
      type = GNUNET_ATS_NET_LOOPBACK;
  }

  /* Check local networks */
  while ((cur != NULL) && (type == GNUNET_ATS_NET_UNSPECIFIED))
  {
    if (addrlen != cur->length)
    {
      cur = cur->next;
      continue;
    }

    if (addr->sa_family == AF_INET)
    {
      struct sockaddr_in * a4 = (struct sockaddr_in *) addr;
      struct sockaddr_in * net4 = (struct sockaddr_in *) cur->network;
      struct sockaddr_in * mask4 = (struct sockaddr_in *) cur->netmask;

      if (((a4->sin_addr.s_addr & mask4->sin_addr.s_addr) & net4->sin_addr.s_addr) == net4->sin_addr.s_addr)
      {
        char * net = strdup (GNUNET_a2s ((const struct sockaddr *) net4, addrlen));
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "`%s' is in network `%s'\n",
            GNUNET_a2s ((const struct sockaddr *)a4, addrlen),
            net);
        GNUNET_free (net);
        type = GNUNET_ATS_NET_LAN;
      }
    }
    if (addr->sa_family == AF_INET6)
    {
      struct sockaddr_in6 * a6 = (struct sockaddr_in6 *) addr;
      struct sockaddr_in6 * net6 = (struct sockaddr_in6 *) cur->network;
      struct sockaddr_in6 * mask6 = (struct sockaddr_in6 *) cur->netmask;

      int res = GNUNET_YES;
      int c = 0;
      for (c = 0; c < 4; c++)
      {
        if (((a6->sin6_addr.__in6_u.__u6_addr32[c] & mask6->sin6_addr.__in6_u.__u6_addr32[c]) | net6->sin6_addr.__in6_u.__u6_addr32[c]) != net6->sin6_addr.__in6_u.__u6_addr32[c])
          res = GNUNET_NO;
      }

      if (res == GNUNET_YES)
      {
        char * net = strdup (GNUNET_a2s ((const struct sockaddr *) net6, addrlen));
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "`%s' is in network `%s'\n",
              GNUNET_a2s ((const struct sockaddr *) a6, addrlen),
              net);
        GNUNET_free (net);
        type = GNUNET_ATS_NET_LAN;
      }
    }
    cur = cur->next;
  }

  /* local network found for this address, default: WAN */
  if (type == GNUNET_ATS_NET_UNSPECIFIED)
    type = GNUNET_ATS_NET_WAN;

  ats.type = htonl (GNUNET_ATS_NETWORK_TYPE);
  ats.value = htonl (type);
  return ats;
}

static int
interface_proc (void *cls, const char *name,
                int isDefault,
                const struct sockaddr *
                addr,
                const struct sockaddr *
                broadcast_addr,
                const struct sockaddr *
                netmask, socklen_t addrlen)
{
  /* Calculate network */
  struct ATS_Network *net = NULL;
  if (addr->sa_family == AF_INET)
  {
    struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;
    struct sockaddr_in *netmask4 = (struct sockaddr_in *) netmask;
    struct sockaddr_in *tmp = NULL;
    struct sockaddr_in network4;

    net = GNUNET_malloc(sizeof (struct ATS_Network) + 2 * sizeof (struct sockaddr_in));
    tmp = (struct sockaddr_in *) &net[1];
    net->network = (struct sockaddr *) &tmp[0];
    net->netmask = (struct sockaddr *) &tmp[1];
    net->length = addrlen;

    network4.sin_family = AF_INET;
    network4.sin_port = htons (0);
#if HAVE_SOCKADDR_IN_SIN_LEN
    network4.sin_len = sizeof (network4);
#endif
    network4.sin_addr.s_addr = (addr4->sin_addr.s_addr & netmask4->sin_addr.s_addr);

    memcpy (net->netmask, netmask4, sizeof (struct sockaddr_in));
    memcpy (net->network, &network4, sizeof (struct sockaddr_in));

    char * netmask = strdup (GNUNET_a2s((struct sockaddr *) net->netmask, addrlen));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding network `%s', netmask `%s'\n",
        GNUNET_a2s((struct sockaddr *) net->network, addrlen),
        netmask);
    GNUNET_free (netmask);

  }

  if (addr->sa_family == AF_INET6)
  {
    struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) addr;
    struct sockaddr_in6 *netmask6 = (struct sockaddr_in6 *) netmask;
    struct sockaddr_in6 * tmp = NULL;
    struct sockaddr_in6 network6;

    net = GNUNET_malloc(sizeof (struct ATS_Network) + 2 * sizeof (struct sockaddr_in6));
    tmp = (struct sockaddr_in6 *) &net[1];
    net->network = (struct sockaddr *) &tmp[0];
    net->netmask = (struct sockaddr *) &tmp[1];
    net->length = addrlen;

    network6.sin6_family = AF_INET6;
    network6.sin6_port = htons (0);
#if HAVE_SOCKADDR_IN_SIN_LEN
    network6.sin6_len = sizeof (network6);
#endif
    int c = 0;
    for (c = 0; c < 4; c++)
    {
      network6.sin6_addr.__in6_u.__u6_addr32[c] = addr6->sin6_addr.__in6_u.__u6_addr32[c] & netmask6->sin6_addr.__in6_u.__u6_addr32[c];
    }

    memcpy (net->netmask, netmask6, sizeof (struct sockaddr_in6));
    memcpy (net->network, &network6, sizeof (struct sockaddr_in6));

    char * netmask = strdup (GNUNET_a2s((struct sockaddr *) net->netmask, addrlen));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding network `%s', netmask `%s'\n",
        GNUNET_a2s((struct sockaddr *) net->network, addrlen),
        netmask);
    GNUNET_free (netmask);
  }

  /* Store in list */
  if (net != NULL)
    GNUNET_CONTAINER_DLL_insert(net_head, net_tail, net);

  return GNUNET_OK;
}

static void
delete_networks ()
{
  struct ATS_Network * cur = net_head;
  while (cur != NULL)
  {
    GNUNET_CONTAINER_DLL_remove(net_head, net_tail, cur);
    GNUNET_free (cur);
    cur = net_head;
  }
}

static void
get_addresses (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  interface_task = GNUNET_SCHEDULER_NO_TASK;
  delete_networks ();
  GNUNET_OS_network_interfaces_list(interface_proc, NULL);

  interface_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MINUTES, get_addresses, NULL);
}

/**
 * Initialize address subsystem.
 *
 * @param cfg configuration to use
 */
void
GAS_addresses_init (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "WAN_QUOTA_IN",
                                                      &wan_quota_in));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "WAN_QUOTA_OUT",
                                                      &wan_quota_out));
  addresses = GNUNET_CONTAINER_multihashmap_create (128);

  interface_task = GNUNET_SCHEDULER_add_now(get_addresses, NULL);
}


/**
 * Free memory of address.
 *
 * @param cls NULL
 * @param key peer identity (unused)
 * @param value the 'struct ATS_Address' to free
 * @return GNUNET_OK (continue to iterate)
 */
static int
free_address_it (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct ATS_Address *aa = value;

  destroy_address (aa);
  return GNUNET_OK;
}


void
GAS_addresses_destroy_all ()
{
  if (addresses != NULL)
    GNUNET_CONTAINER_multihashmap_iterate (addresses, &free_address_it, NULL);
  GNUNET_assert (active_addr_count == 0);
}


/**
 * Shutdown address subsystem.
 */
void
GAS_addresses_done ()
{
  delete_networks ();
  if (interface_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel(interface_task);
    interface_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GAS_addresses_destroy_all ();
  GNUNET_CONTAINER_multihashmap_destroy (addresses);
  addresses = NULL;
}


/* end of gnunet-service-ats_addresses.c */
