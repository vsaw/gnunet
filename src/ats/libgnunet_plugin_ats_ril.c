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
 * @file ats/libgnunet_plugin_ats_ril.c
 * @brief ATS reinforcement learning solver
 * @author Fabian Oehlmann
 * @author Matthias Wachs
 */
#include "libgnunet_plugin_ats_ril.h"

#define LOG(kind,...) GNUNET_log_from (kind, "ats-ril",__VA_ARGS__)

#define RIL_ACTION_INVALID -1
#define RIL_FEATURES_ADDRESS_COUNT (3 + GNUNET_ATS_QualityPropertiesCount)
#define RIL_FEATURES_NETWORK_COUNT 4

#define RIL_DEFAULT_STEP_TIME GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 3000)
#define RIL_DEFAULT_ALGORITHM RIL_ALGO_Q
#define RIL_DEFAULT_DISCOUNT_FACTOR 0.5
#define RIL_DEFAULT_GRADIENT_STEP_SIZE 0.4
#define RIL_DEFAULT_TRACE_DECAY 0.6
#define RIL_EXPLORE_RATIO 0.1

/**
 * ATS reinforcement learning solver
 *
 * General description
 */

/**
 * The actions, how an agent can manipulate the current assignment. I.e. how the bandwidth can be
 * changed for the currently chosen address. Not depicted in the enum are the actions of switching
 * to a particular address. The action of switching to address with index i is depicted by the
 * number (RIL_ACTION_TYPE_NUM + i).
 */
enum RIL_Action_Type
{
  RIL_ACTION_NOTHING = 0,
  RIL_ACTION_BW_IN_DBL = 1,
  RIL_ACTION_BW_IN_HLV = 2,
  RIL_ACTION_BW_IN_INC = 3,
  RIL_ACTION_BW_IN_DEC = 4,
  RIL_ACTION_BW_OUT_DBL = 5,
  RIL_ACTION_BW_OUT_HLV = 6,
  RIL_ACTION_BW_OUT_INC = 7,
  RIL_ACTION_BW_OUT_DEC = 8,
  RIL_ACTION_TYPE_NUM = 9
};

enum RIL_Algorithm
{
  RIL_ALGO_SARSA = 0,
  RIL_ALGO_Q = 1
};

enum RIL_E_Modification
{
  RIL_E_SET,
  RIL_E_ZERO,
  RIL_E_ACCUMULATE,
  RIL_E_REPLACE
};

/**
 * Global learning parameters
 */
struct RIL_Learning_Parameters
{
  /**
   * The TD-algorithm to use
   */
  enum RIL_Algorithm algorithm;

  /**
   * Learning discount factor in the TD-update
   */
  float gamma;

  /**
   * Gradient-descent step-size
   */
  float alpha;

  /**
   * Trace-decay factor for eligibility traces
   */
  float lambda;
};

/**
 * Wrapper for addresses to store them in agent's linked list
 */
struct RIL_Address_Wrapped
{
  /**
   * Next in DLL
   */
  struct RIL_Address_Wrapped *next;

  /**
   * Previous in DLL
   */
  struct RIL_Address_Wrapped *prev;

  /**
   * The address
   */
  struct ATS_Address *address_naked;
};

struct RIL_Peer_Agent
{
  /**
   * Next agent in solver's linked list
   */
  struct RIL_Peer_Agent *next;

  /**
   * Previous agent in solver's linked list
   */
  struct RIL_Peer_Agent *prev;

  /**
   * Environment handle
   */
  struct GAS_RIL_Handle *envi;

  /**
   * Peer ID
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Whether the agent is active or not
   */
  int active;

  /**
   * Number of performed time-steps
   */
  unsigned long long step_count;

  /**
   * Experience matrix W
   */
  double ** W;

  /**
   * Number of rows of W / Number of state-vector features
   */
  unsigned int m;

  /**
   * Number of columns of W / Number of actions
   */
  unsigned int n;

  /**
   * Last perceived state feature vector
   */
  double * s_old;

  /**
   * Last chosen action
   */
  int a_old;

  /**
   * Eligibility trace vector
   */
  double * e;

  /**
   * Address in use
   */
  struct ATS_Address * address_inuse;

  /**
   * Head of addresses DLL
   */
  struct RIL_Address_Wrapped * addresses_head;

  /**
   * Tail of addresses DLL
   */
  struct RIL_Address_Wrapped * addresses_tail;

  /**
   * Inbound bandwidth assigned by the agent
   */
  unsigned long long bw_in;

  /**
   * Outbound bandwidth assigned by the agent
   */
  unsigned long long bw_out;
};

struct RIL_Network
{
  /**
   * ATS network type
   */
  enum GNUNET_ATS_Network_Type type;

  /**
   * Total available inbound bandwidth
   */
  unsigned long long bw_in_available;

  /**
   * Total assigned outbound bandwidth
   */
  unsigned long long bw_in_assigned;

  /**
   * Total available outbound bandwidth
   */
  unsigned long long bw_out_available;

  /**
   * Total assigned outbound bandwidth
   */
  unsigned long long bw_out_assigned;
};

/**
 * A handle for the reinforcement learning solver
 */
struct GAS_RIL_Handle
{
  /**
   *
   */
  struct GNUNET_ATS_PluginEnvironment *plugin_envi;

  /**
   * Statistics handle
   */
  struct GNUNET_STATISTICS_Handle *stats;

  /**
   * Number of performed time-steps
   */
  unsigned long long step_count;

  /**
   * Interval time between steps in milliseconds //TODO? Future Work: Heterogeneous stepping among agents
   */
  struct GNUNET_TIME_Relative step_time;

  /**
   * Task identifier of the next time-step to be executed
   */
  GNUNET_SCHEDULER_TaskIdentifier next_step;

  /**
   * Learning parameters
   */
  struct RIL_Learning_Parameters parameters;

  /**
   * Array of networks with global assignment state
   */
  struct RIL_Network * network_entries;

  /**
   * Networks count
   */
  unsigned int networks_count;

  /**
   * List of active peer-agents
   */
  struct RIL_Peer_Agent * agents_head;
  struct RIL_Peer_Agent * agents_tail;
};

/*
 *  Private functions
 *  ---------------------------
 */

/**
 * Estimate the current action-value for state s and action a
 *
 * @param agent agent performing the estimation
 * @param state s
 * @param action a
 * @return estimation value
 */
static double
agent_estimate_q (struct RIL_Peer_Agent *agent, double *state, int action)
{
  int i;
  double result = 0;

  for (i = 0; i < agent->m; i++)
  {
    result += state[i] * agent->W[action][i];
  }

  return result;
}

/**
 * Decide whether to do exploration (i.e. taking a new action) or exploitation (i.e. taking the
 * currently estimated best action) in the current step
 *
 * @param agent agent performing the step
 * @return yes, if exploring
 */
static int
agent_decide_exploration (struct RIL_Peer_Agent *agent)
{
  //TODO? Future Work: Improve exploration/exploitation trade-off by different mechanisms than e-greedy
  /*
   * An e-greedy replacement could be based on the accuracy of the prediction of the Q-value
   */
  double r = (double) GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
      UINT32_MAX) / (double) UINT32_MAX;

if  (r < RIL_EXPLORE_RATIO)
  {
    return GNUNET_YES;
  }
  return GNUNET_NO;
}

  /**
   * Get the index of the address in the agent's list.
   *
   * @param agent agent handle
   * @param address address handle
   * @return the index, starting with zero
   */
static int
agent_address_get_index (struct RIL_Peer_Agent *agent, struct ATS_Address *address)
{
  int i;
  struct RIL_Address_Wrapped *cur;

  i = -1;
  for (cur = agent->addresses_head; NULL != cur; cur = cur->next)
  {
    i++;
    if (cur->address_naked == address)
    {
      return i;
    }
  }

  return i;
}

/**
 * Gets the wrapped address from the agent's list
 *
 * @param agent agent handle
 * @param address address handle
 * @return wrapped address
 */
static struct RIL_Address_Wrapped *
agent_address_get (struct RIL_Peer_Agent *agent, struct ATS_Address *address)
{
  struct RIL_Address_Wrapped *cur;

  for (cur = agent->addresses_head; NULL != cur; cur = cur->next)
  {
    if (cur->address_naked == address)
    {
      return cur;
    }
  }

  return NULL ;
}

/**
 * Gets the action, with the maximal estimated Q-value (i.e. the one currently estimated to bring the
 * most reward in the future)
 *
 * @param agent agent performing the calculation
 * @param state the state from which to take the action
 * @return the action promising most future reward
 */
static int
agent_get_action_best (struct RIL_Peer_Agent *agent, double *state)
{
  int i;
  int max_i = RIL_ACTION_INVALID;
  double cur_q;
  double max_q = -DBL_MAX;

  for (i = 0; i < agent->n; i++)
  {
    cur_q = agent_estimate_q (agent, state, i);
    if (cur_q > max_q)
    {
      max_q = cur_q;
      max_i = i;
    }
  }

  GNUNET_assert(RIL_ACTION_INVALID != max_i);

  return max_i;
}

/**
 * Gets any action, to explore the action space from that state
 *
 * @param agent agent performing the calculation
 * @param state the state from which to take the action
 * @return any action
 */
static int
agent_get_action_explore (struct RIL_Peer_Agent *agent, double *state)
{
  // TODO?: Future Work: Choose the action for exploration, which has been explored the least in this state
  return GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, agent->n);
}

/**
 * Updates the weights (i.e. coefficients) of the weight vector in matrix W for action a
 *
 * @param agent the agent performing the update
 * @param reward the reward received for the last action
 * @param s_next the new state, the last step got the agent into
 * @param a_prime the new
 */
static void
agent_update_weights (struct RIL_Peer_Agent *agent, double reward, double *s_next, int a_prime)
{
  int i;
  double delta;
  double *theta = agent->W[agent->a_old];

  delta = reward + agent_estimate_q (agent, s_next, a_prime)
      - agent_estimate_q (agent, agent->s_old, agent->a_old);
  for (i = 0; i < agent->m; i++)
  {
    theta[i] += agent->envi->parameters.alpha * delta * (agent->e)[i];
  }
}

/**
 * Changes the eligibility trace vector e in various manners:
 * RIL_E_ACCUMULATE - adds 1 to each component as in accumulating eligibility traces
 * RIL_E_REPLACE - resets each component to 1 as in replacing traces
 * RIL_E_SET - multiplies e with gamma and lambda as in the update rule
 * RIL_E_ZERO - sets e to 0 as in Watkin's Q-learning algorithm when exploring and when initializing
 *
 * @param agent the agent handle
 * @param mod the kind of modification
 */
static void
agent_modify_eligibility (struct RIL_Peer_Agent *agent, enum RIL_E_Modification mod)
{
  int i;
  double *e = agent->e;
  double gamma = agent->envi->parameters.gamma;
  double lambda = agent->envi->parameters.lambda;

  for (i = 0; i < agent->m; i++)
  {
    switch (mod)
    {
    case RIL_E_ACCUMULATE:
      e[i] += 1;
      break;
    case RIL_E_REPLACE:
      e[i] = 1;
      break;
    case RIL_E_SET:
      e[i] = gamma * lambda;
      break;
    case RIL_E_ZERO:
      e[i] = 0;
      break;
    }
  }
}

/**
 * Changes the active assignment suggestion of the handler and invokes the bw_changed callback to
 * notify ATS of its new decision
 *
 * @param solver solver handle
 * @param agent agent handle
 * @param new_address the address which is to be used
 * @param new_bw_in the new amount of inbound bandwidth set for this address
 * @param new_bw_out the new amount of outbound bandwidth set for this address
 * @param silent disables invocation of the bw_changed callback, if GNUNET_YES
 */
static void
envi_set_active_suggestion (struct GAS_RIL_Handle *solver,
    struct RIL_Peer_Agent *agent,
    struct ATS_Address *new_address,
    unsigned long long new_bw_in,
    unsigned long long new_bw_out,
    int silent)
{
  int notify = GNUNET_NO;

  LOG(GNUNET_ERROR_TYPE_DEBUG, "set_active_suggestion()\n");

  //address change
  if (agent->address_inuse != new_address)
  {
    if (NULL != agent->address_inuse)
    {
      agent->address_inuse->active = GNUNET_NO;
      agent->address_inuse->assigned_bw_in.value__ = htonl (0);
      agent->address_inuse->assigned_bw_out.value__ = htonl (0);
    }
    if (NULL != new_address)
    {
      LOG(GNUNET_ERROR_TYPE_DEBUG, "set address active: %s\n", agent->active ? "yes" : "no");
      new_address->active = agent->active;
      new_address->assigned_bw_in.value__ = htonl (agent->bw_in);
      new_address->assigned_bw_out.value__ = htonl (agent->bw_out);
    }
    notify |= GNUNET_YES;
  }

  if (new_address)
  {
    //activity change
    if (new_address->active != agent->active)
    {
      new_address->active = agent->active;
    }

    //bw change
    if (agent->bw_in != new_bw_in)
    {
      agent->bw_in = new_bw_in;
      new_address->assigned_bw_in.value__ = htonl (new_bw_out);
      notify |= GNUNET_YES;
    }
    if (agent->bw_out != new_bw_out)
    {
      agent->bw_out = new_bw_out;
      new_address->assigned_bw_out.value__ = htonl (new_bw_out);
      notify |= GNUNET_YES;
    }
  }

  if (notify && agent->active && (GNUNET_NO == silent))
  {
    if (new_address)
    {
      solver->plugin_envi->bandwidth_changed_cb (solver->plugin_envi->bw_changed_cb_cls,
          new_address);
    }
    else if (agent->address_inuse)
    {
      GNUNET_assert(0 == ntohl (agent->address_inuse->assigned_bw_in.value__));
      GNUNET_assert(0 == ntohl (agent->address_inuse->assigned_bw_out.value__));
      agent->bw_in = 0;
      agent->bw_out = 0;
      //disconnect
      solver->plugin_envi->bandwidth_changed_cb (solver->plugin_envi->bw_changed_cb_cls,
          agent->address_inuse);
    }
  }
  agent->address_inuse = new_address;
}

/**
 * Allocates a state vector and fills it with the features present
 *
 * @param solver the solver handle
 * @return pointer to the state vector
 */
static double *
envi_get_state (struct GAS_RIL_Handle *solver, struct RIL_Peer_Agent *agent)
{
  int i;
  int k;
  struct RIL_Network *net;
  double *state = GNUNET_malloc (sizeof (double) * agent->m);
  struct RIL_Address_Wrapped *cur_address;
  const double *properties;

  for (i = 0; i < solver->networks_count; i++)
  {
    net = &solver->network_entries[i];
    state[i * RIL_FEATURES_NETWORK_COUNT + 0] = (double) net->bw_in_assigned;
    state[i * RIL_FEATURES_NETWORK_COUNT + 1] = (double) net->bw_in_available;
    state[i * RIL_FEATURES_NETWORK_COUNT + 2] = (double) net->bw_out_assigned;
    state[i * RIL_FEATURES_NETWORK_COUNT + 3] = (double) net->bw_out_available;
  }

  i = i * RIL_FEATURES_NETWORK_COUNT; //first address feature

  for (cur_address = agent->addresses_head; NULL != cur_address; cur_address = cur_address->next)
  {
    state[i++] = cur_address->address_naked->active;
    state[i++] = cur_address->address_naked->active ? agent->bw_in : 0;
    state[i++] = cur_address->address_naked->active ? agent->bw_out : 0;
    properties = solver->plugin_envi->get_property (solver->plugin_envi->get_property_cls,
        cur_address->address_naked);
    for (k = 0; k < GNUNET_ATS_QualityPropertiesCount; k++)
    {
      state[i++] = properties[k];
    }
  }

  return state;
}

/**
 * For all networks a peer has an address in, this gets the maximum bandwidth which could
 * theoretically be available in one of the networks. This is used for bandwidth normalization.
 *
 * @param solver the solver handle
 * @param agent the agent handle
 * @param direction_in whether the inbound bandwidth should be considered. Returns the maximum outbound bandwidth if GNUNET_NO
 */
static long long unsigned
ril_get_max_bw (struct RIL_Peer_Agent *agent, int direction_in)
{
  /*
   * get the maximum bandwidth possible for a peer, e.g. among all addresses which addresses'
   * network could provide the maximum bandwidth if all that bandwidth was used on that one peer.
   */
  int max = 0;
  struct RIL_Address_Wrapped *cur;
  struct RIL_Network *net;

  for (cur = agent->addresses_head; NULL != cur; cur = cur->next)
  {
    net = cur->address_naked->solver_information;
    if (direction_in)
    {
      if (net->bw_in_available > max)
      {
        max = net->bw_in_available;
      }
    }
    else
    {
      if (net->bw_out_available > max)
      {
        max = net->bw_out_available;
      }
    }
  }
  return max;
}

/**
 * Get the index of the quality-property in question
 *
 * @param type the quality property type
 * @return the index
 */
static int
ril_find_property_index (uint32_t type)
{
  int existing_types[] = GNUNET_ATS_QualityProperties;
  int c;
  for (c = 0; c < GNUNET_ATS_QualityPropertiesCount; c++)
    if (existing_types[c] == type)
      return c;
  return GNUNET_SYSERR;
}

/**
 * Gets the reward for the last performed step
 *
 * @param solver solver handle
 * @return the reward
 */
static double
envi_get_reward (struct GAS_RIL_Handle *solver, struct RIL_Peer_Agent *agent)
{
  /*
   * - Match the preferences of the peer with the current assignment
   * - Validity of the solution
   */
  const double *preferences;
  const double *properties;
  double pref_match = 0;
  double bw_norm;
  struct RIL_Network *net;
  int prop_index;

  preferences = solver->plugin_envi->get_preferences (solver->plugin_envi->get_preference_cls,
      &agent->peer);
  properties = solver->plugin_envi->get_property (solver->plugin_envi->get_property_cls,
      agent->address_inuse);
  prop_index = ril_find_property_index (GNUNET_ATS_QUALITY_NET_DELAY);
  pref_match += preferences[GNUNET_ATS_PREFERENCE_LATENCY] * (3 - properties[prop_index]); //invert property as we want to maximize for lower latencies
  bw_norm = GNUNET_MAX(2, (((
                  ((double) agent->bw_in / (double) ril_get_max_bw(agent, GNUNET_YES)) +
                  ((double) agent->bw_out / (double) ril_get_max_bw(agent, GNUNET_NO))
              ) / 2
          ) + 1));
  pref_match += preferences[GNUNET_ATS_PREFERENCE_BANDWIDTH] * bw_norm;

  net = agent->address_inuse->solver_information;
  if ((net->bw_in_assigned > net->bw_in_available) || (net->bw_out_assigned > net->bw_out_available))
  {
    return -1;
  }

  return pref_match;
}

/**
 * Doubles the bandwidth for the active address
 *
 * @param solver solver handle
 * @param agent agent handle
 * @param direction_in if GNUNET_YES, change inbound bandwidth, otherwise the outbound bandwidth
 */
static void
envi_action_bw_double (struct GAS_RIL_Handle *solver,
    struct RIL_Peer_Agent *agent,
    int direction_in)
{
  if (direction_in)
  {
    envi_set_active_suggestion (solver, agent, agent->address_inuse, agent->bw_in * 2,
        agent->bw_out, GNUNET_NO);
  }
  else
  {
    envi_set_active_suggestion (solver, agent, agent->address_inuse, agent->bw_in,
        agent->bw_out * 2, GNUNET_NO);
  }
}

/**
 * Cuts the bandwidth for the active address in half. The least amount of bandwidth suggested, is
 * the minimum bandwidth for a peer, in order to not invoke a disconnect.
 *
 * @param solver solver handle
 * @param agent agent handle
 * @param direction_in if GNUNET_YES, change inbound bandwidth, otherwise change the outbound
 * bandwidth
 */
static void
envi_action_bw_halven (struct GAS_RIL_Handle *solver,
    struct RIL_Peer_Agent *agent,
    int direction_in)
{
  uint32_t min_bw = ntohl (GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT.value__);
  unsigned long long new_bw;

  if (direction_in)
  {
    new_bw = agent->bw_in / 2;
    if (new_bw < min_bw)
      new_bw = min_bw;
    envi_set_active_suggestion (solver, agent, agent->address_inuse, new_bw, agent->bw_out,
        GNUNET_NO);
  }
  else
  {
    new_bw = agent->bw_out / 2;
    if (new_bw < min_bw)
      new_bw = min_bw;
    envi_set_active_suggestion (solver, agent, agent->address_inuse, agent->bw_in, new_bw,
        GNUNET_NO);
  }
}

/**
 * Increases the bandwidth by 5 times the minimum bandwidth for the active address.
 *
 * @param solver solver handle
 * @param agent agent handle
 * @param direction_in if GNUNET_YES, change inbound bandwidth, otherwise change the outbound
 * bandwidth
 */
static void
envi_action_bw_inc (struct GAS_RIL_Handle *solver, struct RIL_Peer_Agent *agent, int direction_in)
{
  uint32_t min_bw = ntohl (GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT.value__);

  if (direction_in)
  {
    envi_set_active_suggestion (solver, agent, agent->address_inuse, agent->bw_in + (5 * min_bw),
        agent->bw_out, GNUNET_NO);
  }
  else
  {
    envi_set_active_suggestion (solver, agent, agent->address_inuse, agent->bw_in,
        agent->bw_out + (5 * min_bw), GNUNET_NO);
  }
}

/**
 * Decreases the bandwidth by 5 times the minimum bandwidth for the active address. The least amount
 * of bandwidth suggested, is the minimum bandwidth for a peer, in order to not invoke a disconnect.
 *
 * @param solver solver handle
 * @param agent agent handle
 * @param direction_in if GNUNET_YES, change inbound bandwidth, otherwise change the outbound
 * bandwidth
 */
static void
envi_action_bw_dec (struct GAS_RIL_Handle *solver, struct RIL_Peer_Agent *agent, int direction_in)
{
  uint32_t min_bw = ntohl (GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT.value__);
  unsigned long long new_bw;

  if (direction_in)
  {
    new_bw = agent->bw_in - (5 * min_bw);
    if (new_bw < min_bw)
      new_bw = min_bw;
    envi_set_active_suggestion (solver, agent, agent->address_inuse, new_bw, agent->bw_out,
        GNUNET_NO);
  }
  else
  {
    new_bw = agent->bw_out - (5 * min_bw);
    if (new_bw < min_bw)
      new_bw = min_bw;
    envi_set_active_suggestion (solver, agent, agent->address_inuse, agent->bw_in, new_bw,
        GNUNET_NO);
  }
}

/**
 * Switches to the address given by its index
 *
 * @param solver solver handle
 * @param agent agent handle
 * @param address_index index of the address as it is saved in the agent's list, starting with zero
 */
static void
envi_action_address_switch (struct GAS_RIL_Handle *solver,
    struct RIL_Peer_Agent *agent,
    unsigned int address_index)
{
  struct RIL_Address_Wrapped *cur;
  int i = 0;

  for (cur = agent->addresses_head; NULL != cur; cur = cur->next)
  {
    if (i == address_index)
    {
      envi_set_active_suggestion (solver, agent, cur->address_naked, agent->bw_in, agent->bw_out,
          GNUNET_NO);
      return;
    }

    i++;
  }

  //no address with address_index exists, in this case this action should not be callable
  GNUNET_assert(GNUNET_NO);
}

/**
 * Puts the action into effect by calling the according function
 *
 * @param solver solver handle
 * @param action action to perform by the solver
 */
static void
envi_do_action (struct GAS_RIL_Handle *solver, struct RIL_Peer_Agent *agent, int action)
{
  int address_index;

  switch (action)
  {
  case RIL_ACTION_NOTHING:
    break;
  case RIL_ACTION_BW_IN_DBL:
    envi_action_bw_double (solver, agent, GNUNET_YES);
    break;
  case RIL_ACTION_BW_IN_HLV:
    envi_action_bw_halven (solver, agent, GNUNET_YES);
    break;
  case RIL_ACTION_BW_IN_INC:
    envi_action_bw_inc (solver, agent, GNUNET_YES);
    break;
  case RIL_ACTION_BW_IN_DEC:
    envi_action_bw_dec (solver, agent, GNUNET_YES);
    break;
  case RIL_ACTION_BW_OUT_DBL:
    envi_action_bw_double (solver, agent, GNUNET_NO);
    break;
  case RIL_ACTION_BW_OUT_HLV:
    envi_action_bw_halven (solver, agent, GNUNET_NO);
    break;
  case RIL_ACTION_BW_OUT_INC:
    envi_action_bw_inc (solver, agent, GNUNET_NO);
    break;
  case RIL_ACTION_BW_OUT_DEC:
    envi_action_bw_dec (solver, agent, GNUNET_NO);
    break;
  default:
    if ((action >= RIL_ACTION_TYPE_NUM) && (action < agent->n)) //switch address action
    {
      address_index = action - RIL_ACTION_TYPE_NUM;

      GNUNET_assert(address_index >= 0);
      GNUNET_assert(
          address_index <= agent_address_get_index (agent, agent->addresses_tail->address_naked));

      envi_action_address_switch (solver, agent, address_index);
      break;
    }
    // error - action does not exist
    GNUNET_assert(GNUNET_NO);
  }
}

/**
 * Performs one step of the Markov Decision Process. Other than in the literature the step starts
 * after having done the last action a_old. It observes the new state s_next and the reward
 * received. Then the coefficient update is done according to the SARSA or Q-learning method. The
 * next action is put into effect.
 *
 * @param agent the agent performing the step
 */
static void
agent_step (struct RIL_Peer_Agent *agent)
{
  int a_next = RIL_ACTION_INVALID;
  double *s_next;
  double reward;

  s_next = envi_get_state (agent->envi, agent);
  reward = envi_get_reward (agent->envi, agent);

  LOG(GNUNET_ERROR_TYPE_DEBUG, "agent_step() with algorithm %s\n",
      agent->envi->parameters.algorithm ? "Q" : "SARSA");

  switch (agent->envi->parameters.algorithm)
  {
  case RIL_ALGO_SARSA:
    agent_modify_eligibility (agent, RIL_E_SET);
    if (agent_decide_exploration (agent))
    {
      a_next = agent_get_action_explore (agent, s_next);
    }
    else
    {
      a_next = agent_get_action_best (agent, s_next);
    }
    if (RIL_ACTION_INVALID != agent->a_old)
    {
      //updates weights with selected action (on-policy), if not first step
      agent_update_weights (agent, reward, s_next, a_next);
    }
    break;

  case RIL_ALGO_Q:
    a_next = agent_get_action_best (agent, s_next);
    if (RIL_ACTION_INVALID != agent->a_old)
    {
      //updates weights with best action, disregarding actually selected action (off-policy), if not first step
      agent_update_weights (agent, reward, s_next, a_next);
    }
    if (agent_decide_exploration (agent))
    {
      a_next = agent_get_action_explore (agent, s_next);
      agent_modify_eligibility (agent, RIL_E_ZERO);
    }
    else
    {
      a_next = agent_get_action_best (agent, s_next);
      agent_modify_eligibility (agent, RIL_E_SET);
    }
    break;
  }

  GNUNET_assert(RIL_ACTION_INVALID != a_next);

  agent_modify_eligibility (agent, RIL_E_ACCUMULATE);

  envi_do_action (agent->envi, agent, a_next);

  GNUNET_free(agent->s_old);
  agent->s_old = s_next;
  agent->a_old = a_next;

  agent->step_count += 1;
}

/**
 * Cycles through all agents and lets the active ones do a step. Schedules the next step.
 *
 * @param solver the solver handle
 * @param tc task context for the scheduler
 */
static void
ril_periodic_step (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GAS_RIL_Handle *solver = cls;
  struct RIL_Peer_Agent *cur;

  LOG(GNUNET_ERROR_TYPE_DEBUG, "RIL step number %d\n", solver->step_count);

  for (cur = solver->agents_head; NULL != cur; cur = cur->next)
  {
    if (cur->active && cur->address_inuse)
    {
      agent_step (cur);
    }
  }

  solver->step_count += 1;
  solver->next_step = GNUNET_SCHEDULER_add_delayed (solver->step_time, &ril_periodic_step, solver);
}

/**
 * Initialize an agent without addresses and its knowledge base
 *
 * @param s ril solver
 * @param peer the one in question
 * @return handle to the new agent
 */
static struct RIL_Peer_Agent *
agent_init (void *s, const struct GNUNET_PeerIdentity *peer)
{
  int i;
  struct GAS_RIL_Handle * solver = s;
  struct RIL_Peer_Agent * agent = GNUNET_malloc (sizeof (struct RIL_Peer_Agent));

  agent->envi = solver;
  agent->peer = *peer;
  agent->step_count = 0;
  agent->active = GNUNET_NO;
  agent->n = RIL_ACTION_TYPE_NUM;
  agent->m = solver->networks_count * RIL_FEATURES_NETWORK_COUNT;
  agent->W = (double **) GNUNET_malloc (sizeof (double *) * agent->n);
  for (i = 0; i < agent->n; i++)
  {
    agent->W[i] = (double *) GNUNET_malloc (sizeof (double) * agent->m);
  }
  agent->a_old = RIL_ACTION_INVALID;
  agent->s_old = envi_get_state (solver, agent);
  agent->e = (double *) GNUNET_malloc (sizeof (double) * agent->m);
  agent_modify_eligibility (agent, RIL_E_ZERO);

  GNUNET_CONTAINER_DLL_insert_tail(solver->agents_head, solver->agents_tail, agent);

  return agent;
}

/**
 * Deallocate agent
 *
 * @param s solver handle
 * @param agent the agent to retire
 */
static void
agent_die (struct GAS_RIL_Handle *solver, struct RIL_Peer_Agent *agent)
{
  int i;

  for (i = 0; i < agent->n; i++)
  {
    GNUNET_free(agent->W[i]);
  }
  GNUNET_free(agent->W);
  GNUNET_free(agent->e);
  GNUNET_free(agent->s_old);
  GNUNET_free(agent);
}

/**
 * Returns the agent for a peer
 *
 * @param s solver handle
 * @param peer identity of the peer
 * @param create whether to create an agent if none is allocated yet
 * @return agent
 */
static struct RIL_Peer_Agent *
ril_get_agent (struct GAS_RIL_Handle *solver, const struct GNUNET_PeerIdentity *peer, int create)
{
  struct RIL_Peer_Agent *cur;

  for (cur = solver->agents_head; NULL != cur; cur = cur->next)
  {
    if (0 == memcmp (peer, &cur->peer, sizeof(struct GNUNET_PeerIdentity)))
    {
      return cur;
    }
  }

  if (create)
  {
    return agent_init (solver, peer);
  }
  return NULL ;
}

/**
 * Lookup network struct by type
 *
 * @param s the solver handle
 * @param type the network type
 * @return the network struct
 */
static struct RIL_Network *
ril_get_network (struct GAS_RIL_Handle *s, uint32_t type)
{
  int i;

  for (i = 0; i < s->networks_count; i++)
  {
    if (s->network_entries[i].type == type)
    {
      return &s->network_entries[i];
    }
  }
  return NULL ;
}

/**
 * Determine whether at least the minimum bandwidth is set for the network. Otherwise the network is
 * considered inactive and not used. Addresses in an inactive network are ignored.
 *
 * @param solver solver handle
 * @param network the network type
 * @return whether or not the network is considered active
 */
static int
ril_network_is_active (struct GAS_RIL_Handle *solver, enum GNUNET_ATS_Network_Type network)
{
  struct RIL_Network *net;
  uint32_t min_bw = ntohl (GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT.value__);

  net = ril_get_network (solver, network);
  if (net->bw_out_available < min_bw)
    return GNUNET_NO;
  return GNUNET_YES;
}

/**
 * Cuts a slice out of a vector of elements. This is used to decrease the size of the matrix storing
 * the reward function approximation. It copies the memory, which is not cut, to the new vector,
 * frees the memory of the old vector, and redirects the pointer to the new one.
 *
 * @param old pointer to the pointer to the first element of the vector
 * @param element_size byte size of the vector elements
 * @param hole_start the first element to cut out
 * @param hole_length the number of elements to cut out
 * @param old_length the length of the old vector
 */
static void
ril_cut_from_vector (void **old,
    size_t element_size,
    unsigned int hole_start,
    unsigned int hole_length,
    unsigned int old_length)
{
  char *tmpptr;
  char *oldptr = (char *) *old;
  size_t size;
  unsigned int bytes_before;
  unsigned int bytes_hole;
  unsigned int bytes_after;

  GNUNET_assert(old_length > hole_length);
  GNUNET_assert(old_length >= (hole_start + hole_length));

  size = element_size * (old_length - hole_length);

  bytes_before = element_size * hole_start;
  bytes_hole = element_size * hole_length;
  bytes_after = element_size * (old_length - hole_start - hole_length);

  if (0 == size)
  {
    tmpptr = NULL;
  }
  else
  {
    tmpptr = GNUNET_malloc (size);
    memcpy (tmpptr, oldptr, bytes_before);
    memcpy (tmpptr + bytes_before, oldptr + (bytes_before + bytes_hole), bytes_after);
  }
  if (NULL != *old)
  {
    GNUNET_free(*old);
  }
  *old = (void *) tmpptr;
}

/*
 *  Solver API functions
 *  ---------------------------
 */

/**
 * Change relative preference for quality in solver
 *
 * @param solver the solver handle
 * @param peer the peer to change the preference for
 * @param kind the kind to change the preference
 * @param pref_rel the normalized preference value for this kind over all clients
 */
void
GAS_ril_address_change_preference (void *s,
    const struct GNUNET_PeerIdentity *peer,
    enum GNUNET_ATS_PreferenceKind kind,
    double pref_rel)
{
  LOG(GNUNET_ERROR_TYPE_DEBUG,
      "API_address_change_preference() Preference '%s' for peer '%s' changed to %.2f \n",
      GNUNET_ATS_print_preference_type (kind), GNUNET_i2s (peer), pref_rel);
  /*
   * Nothing to do here. Preferences are considered during reward calculation.
   */
}

/**
 * Entry point for the plugin
 *
 * @param cls pointer to the 'struct GNUNET_ATS_PluginEnvironment'
 */
void *
libgnunet_plugin_ats_ril_init (void *cls)
{
  struct GNUNET_ATS_PluginEnvironment *env = cls;
  struct GAS_RIL_Handle *solver = GNUNET_new (struct GAS_RIL_Handle);
  struct RIL_Network * cur;
  int c;
  unsigned long long tmp;
  char *string;

  LOG(GNUNET_ERROR_TYPE_DEBUG, "API_init() Initializing RIL solver\n");

  GNUNET_assert(NULL != env);
  GNUNET_assert(NULL != env->cfg);
  GNUNET_assert(NULL != env->stats);
  GNUNET_assert(NULL != env->bandwidth_changed_cb);
  GNUNET_assert(NULL != env->get_preferences);
  GNUNET_assert(NULL != env->get_property);

  if (GNUNET_OK
      != GNUNET_CONFIGURATION_get_value_time (env->cfg, "ats", "RIL_STEP_TIME", &solver->step_time))
  {
    solver->step_time = RIL_DEFAULT_STEP_TIME;
  }
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string (env->cfg, "ats", "RIL_ALGORITHM", &string)
      && NULL != string && 0 == strcmp (string, "SARSA"))
  {
    solver->parameters.algorithm = RIL_ALGO_SARSA;
  }
  else
  {
    solver->parameters.algorithm = RIL_DEFAULT_ALGORITHM;
  }
  if (GNUNET_OK
      == GNUNET_CONFIGURATION_get_value_size (env->cfg, "ats", "RIL_DISCOUNT_FACTOR", &tmp))
  {
    solver->parameters.gamma = (double) tmp / 100;
  }
  else
  {
    solver->parameters.gamma = RIL_DEFAULT_DISCOUNT_FACTOR;
  }
  if (GNUNET_OK
      == GNUNET_CONFIGURATION_get_value_size (env->cfg, "ats", "RIL_GRADIENT_STEP_SIZE", &tmp))
  {
    solver->parameters.alpha = (double) tmp / 100;
  }
  else
  {
    solver->parameters.alpha = RIL_DEFAULT_GRADIENT_STEP_SIZE;
  }
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (env->cfg, "ats", "RIL_TRACE_DECAY", &tmp))
  {
    solver->parameters.lambda = (double) tmp / 100;
  }
  else
  {
    solver->parameters.lambda = RIL_DEFAULT_TRACE_DECAY;
  }

  env->sf.s_add = &GAS_ril_address_add;
  env->sf.s_address_update_property = &GAS_ril_address_property_changed;
  env->sf.s_address_update_session = &GAS_ril_address_session_changed;
  env->sf.s_address_update_inuse = &GAS_ril_address_inuse_changed;
  env->sf.s_address_update_network = &GAS_ril_address_change_network;
  env->sf.s_get = &GAS_ril_get_preferred_address;
  env->sf.s_get_stop = &GAS_ril_stop_get_preferred_address;
  env->sf.s_pref = &GAS_ril_address_change_preference;
  env->sf.s_feedback = &GAS_ril_address_preference_feedback;
  env->sf.s_del = &GAS_ril_address_delete;
  env->sf.s_bulk_start = &GAS_ril_bulk_start;
  env->sf.s_bulk_stop = &GAS_ril_bulk_stop;

  solver->plugin_envi = env;
  solver->networks_count = env->network_count;
  solver->network_entries = GNUNET_malloc (env->network_count * sizeof (struct RIL_Network));
  solver->step_count = 0;

  for (c = 0; c < env->network_count; c++)
  {
    cur = &solver->network_entries[c];
    cur->type = env->networks[c];
    cur->bw_in_available = env->in_quota[c];
    cur->bw_in_assigned = 0;
    cur->bw_out_available = env->out_quota[c];
    cur->bw_out_assigned = 0;
  }

  solver->next_step = GNUNET_SCHEDULER_add_delayed (
      GNUNET_TIME_relative_multiply (GNUNET_TIME_relative_get_millisecond_ (), 1000),
      &ril_periodic_step, solver);

  return solver;
}

/**
 * Exit point for the plugin
 *
 * @param cls the solver handle
 */
void *
libgnunet_plugin_ats_ril_done (void *cls)
{
  struct GAS_RIL_Handle *s = cls;
  struct RIL_Peer_Agent *cur_agent;
  struct RIL_Peer_Agent *next_agent;

  LOG(GNUNET_ERROR_TYPE_DEBUG, "API_done() Shutting down RIL solver\n");

  cur_agent = s->agents_head;
  while (NULL != cur_agent)
  {
    next_agent = cur_agent->next;
    GNUNET_CONTAINER_DLL_remove(s->agents_head, s->agents_tail, cur_agent);
    agent_die (s, cur_agent);
    cur_agent = next_agent;
  }

  GNUNET_SCHEDULER_cancel (s->next_step);
  GNUNET_free(s->network_entries);
  GNUNET_free(s);

  return NULL ;
}

/**
 * Add a new address for a peer to the solver
 *
 * The address is already contained in the addresses hashmap!
 *
 * @param solver the solver Handle
 * @param address the address to add
 * @param network network type of this address
 */
void
GAS_ril_address_add (void *solver, struct ATS_Address *address, uint32_t network)
{
  struct GAS_RIL_Handle *s = solver;
  struct RIL_Peer_Agent *agent;
  struct RIL_Address_Wrapped *address_wrapped;
  struct RIL_Network *net;
  unsigned int m_new;
  unsigned int m_old;
  unsigned int n_new;
  unsigned int n_old;
  int i;
  unsigned int zero;
  uint32_t min_bw = ntohl (GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT.value__);

  net = ril_get_network (s, network);
  address->solver_information = net;

  if (!ril_network_is_active (s, network))
  {
    LOG(GNUNET_ERROR_TYPE_DEBUG,
        "API_address_add() Did not add %s address %p for peer '%s', network does not have enough bandwidth\n",
        address->plugin, address->addr, GNUNET_i2s (&address->peer));
    return;
  }

  agent = ril_get_agent (s, &address->peer, GNUNET_YES);

  //add address
  address_wrapped = GNUNET_malloc (sizeof (struct RIL_Address_Wrapped));
  address_wrapped->address_naked = address;
  GNUNET_CONTAINER_DLL_insert_tail(agent->addresses_head, agent->addresses_tail, address_wrapped);

  //increase size of W
  m_new = agent->m + RIL_FEATURES_ADDRESS_COUNT;
  m_old = agent->m;
  n_new = agent->n + 1;
  n_old = agent->n;

  GNUNET_array_grow(agent->W, agent->n, n_new);
  for (i = 0; i < n_new; i++)
  {
    if (i < n_old)
    {
      agent->m = m_old;
      GNUNET_array_grow(agent->W[i], agent->m, m_new);
    }
    else
    {
      zero = 0;
      GNUNET_array_grow(agent->W[i], zero, m_new);
    }
  }

  //increase size of old state vector
  agent->m = m_old;
  GNUNET_array_grow(agent->s_old, agent->m, m_new);

  agent->m = m_old;
  GNUNET_array_grow(agent->e, agent->m, m_new);

  if (NULL == agent->address_inuse)
  {
    net->bw_in_assigned += min_bw;
    net->bw_out_assigned += min_bw;
    envi_set_active_suggestion (s, agent, address, min_bw, min_bw, GNUNET_NO);
  }

  LOG(GNUNET_ERROR_TYPE_DEBUG, "API_address_add() Added %s %s address %p for peer '%s'\n",
      address->active ? "active" : "inactive", address->plugin, address->addr,
      GNUNET_i2s (&address->peer));
}

/**
 * Delete an address in the solver
 *
 * The address is not contained in the address hashmap anymore!
 *
 * @param solver the solver handle
 * @param address the address to remove
 * @param session_only delete only session not whole address
 */
void
GAS_ril_address_delete (void *solver, struct ATS_Address *address, int session_only)
{
  struct GAS_RIL_Handle *s = solver;
  struct RIL_Peer_Agent *agent;
  struct RIL_Address_Wrapped *address_wrapped;
  int address_was_used = address->active;
  int address_index;
  unsigned int m_new;
  unsigned int n_new;
  int i;
  struct RIL_Network *net;
  uint32_t min_bw = ntohl (GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT.value__);

  LOG(GNUNET_ERROR_TYPE_DEBUG, "API_address_delete() Delete %s%s %s address %p for peer '%s'\n",
      session_only ? "session for " : "", address->active ? "active" : "inactive", address->plugin,
      address->addr, GNUNET_i2s (&address->peer));

  agent = ril_get_agent (s, &address->peer, GNUNET_NO);
  if (NULL == agent)
  {
    net = address->solver_information;
    GNUNET_assert(!ril_network_is_active (s, net->type));
    LOG(GNUNET_ERROR_TYPE_DEBUG,
        "No agent allocated for peer yet, since address was in inactive network\n");
    return;
  }

  address_index = agent_address_get_index (agent, address);
  address_wrapped = agent_address_get (agent, address);

  if (NULL == address_wrapped)
  {
    net = address->solver_information;
    GNUNET_assert(!ril_network_is_active (s, net->type));
    LOG(GNUNET_ERROR_TYPE_DEBUG,
        "Address not considered by agent, address was in inactive network\n");
    return;
  }

  GNUNET_CONTAINER_DLL_remove(agent->addresses_head, agent->addresses_tail, address_wrapped);
  GNUNET_free(address_wrapped);

  //decrease W
  m_new = agent->m - RIL_FEATURES_ADDRESS_COUNT;
  n_new = agent->n - 1;

  for (i = 0; i < agent->n; i++)
  {
    ril_cut_from_vector ((void **) &agent->W[i], sizeof(double),
        ((s->networks_count * RIL_FEATURES_NETWORK_COUNT)
            + (address_index * RIL_FEATURES_ADDRESS_COUNT)), RIL_FEATURES_ADDRESS_COUNT, agent->m);
  }
  GNUNET_free(agent->W[RIL_ACTION_TYPE_NUM + address_index]);
  ril_cut_from_vector ((void **) &agent->W, sizeof(double *), RIL_ACTION_TYPE_NUM + address_index,
      1, agent->n);
  //correct last action
  if (agent->a_old > (RIL_ACTION_TYPE_NUM + address_index))
  {
    agent->a_old -= 1;
  }
  else if (agent->a_old == (RIL_ACTION_TYPE_NUM + address_index))
  {
    agent->a_old = RIL_ACTION_INVALID;
  }
  //decrease old state vector and eligibility vector
  ril_cut_from_vector ((void **) &agent->s_old, sizeof(double),
      ((s->networks_count * RIL_FEATURES_NETWORK_COUNT)
          + (address_index * RIL_FEATURES_ADDRESS_COUNT)), RIL_FEATURES_ADDRESS_COUNT, agent->m);
  ril_cut_from_vector ((void **) &agent->e, sizeof(double),
      ((s->networks_count * RIL_FEATURES_NETWORK_COUNT)
          + (address_index * RIL_FEATURES_ADDRESS_COUNT)), RIL_FEATURES_ADDRESS_COUNT, agent->m);
  agent->m = m_new;
  agent->n = n_new;

  LOG(GNUNET_ERROR_TYPE_DEBUG, "address was used: %s\n", address_was_used ? "yes" : "no");

  if (address_was_used)
  {
    net = address->solver_information;
    net->bw_in_assigned -= agent->bw_in;
    net->bw_out_assigned -= agent->bw_out;

    if (NULL != agent->addresses_head) //if peer has an address left, use it
    {
      LOG(GNUNET_ERROR_TYPE_DEBUG, "address left: %p\n",
          agent->addresses_head->address_naked->addr);
      //TODO? check if network/bandwidth update can be done more clever/elegant at different function
      envi_set_active_suggestion (s, agent, agent->addresses_head->address_naked, min_bw, min_bw,
          GNUNET_NO);
      net = agent->addresses_head->address_naked->solver_information;
      net->bw_in_assigned -= min_bw;
      net->bw_out_assigned -= min_bw;
    }
    else
    {
      LOG(GNUNET_ERROR_TYPE_DEBUG, "no address left => disconnect\n");

      envi_set_active_suggestion (s, agent, NULL, 0, 0, GNUNET_NO);
    }
  }

  LOG(GNUNET_ERROR_TYPE_DEBUG, "Address deleted\n");
}

/**
 * Update the properties of an address in the solver
 *
 * @param solver solver handle
 * @param address the address
 * @param type the ATSI type in HBO
 * @param abs_value the absolute value of the property
 * @param rel_value the normalized value
 */
void
GAS_ril_address_property_changed (void *solver,
    struct ATS_Address *address,
    uint32_t type,
    uint32_t abs_value,
    double rel_value)
{
  LOG(GNUNET_ERROR_TYPE_DEBUG,
      "API_address_property_changed() Property '%s' for peer '%s' address %p changed "
          "to %.2f \n", GNUNET_ATS_print_property_type (type), GNUNET_i2s (&address->peer),
      address->addr, rel_value);
  /*
   * Nothing to do here, properties are considered in every reward calculation
   */
}

/**
 * Update the session of an address in the solver
 *
 * NOTE: values in addresses are already updated
 *
 * @param solver solver handle
 * @param address the address
 * @param cur_session the current session
 * @param new_session the new session
 */
void
GAS_ril_address_session_changed (void *solver,
    struct ATS_Address *address,
    uint32_t cur_session,
    uint32_t new_session)
{
  /*
   * TODO? Future Work: Potentially add session activity as a feature in state vector
   */
  LOG(GNUNET_ERROR_TYPE_DEBUG, "API_address_session_changed()\n");
}

/**
 * Notify the solver that an address is (not) actively used by transport
 * to communicate with a remote peer
 *
 * NOTE: values in addresses are already updated
 *
 * @param solver solver handle
 * @param address the address
 * @param in_use usage state
 */
void
GAS_ril_address_inuse_changed (void *solver, struct ATS_Address *address, int in_use)
{
  /* Nothing to do here.
   * Possible TODO? Future Work: Use usage as state vector
   */
  LOG(GNUNET_ERROR_TYPE_DEBUG,
      "API_address_inuse_changed() Usage for %s address of peer '%s' changed to %s\n",
      address->plugin, GNUNET_i2s (&address->peer), (GNUNET_YES == in_use) ? "USED" : "UNUSED");
}

/**
 * Notify solver that the network an address is located in has changed
 *
 * NOTE: values in addresses are already updated
 *
 * @param solver solver handle
 * @param address the address
 * @param current_network the current network
 * @param new_network the new network
 */
void
GAS_ril_address_change_network (void *solver,
    struct ATS_Address *address,
    uint32_t current_network,
    uint32_t new_network)
{
  struct GAS_RIL_Handle *s = solver;
  struct RIL_Peer_Agent *agent;
  struct RIL_Network *net;
  uint32_t min_bw = ntohl (GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT.value__);

  LOG(GNUNET_ERROR_TYPE_DEBUG, "API_address_change_network() Network type changed, moving "
      "%s address of peer %s from '%s' to '%s'\n",
      (GNUNET_YES == address->active) ? "active" : "inactive", GNUNET_i2s (&address->peer),
      GNUNET_ATS_print_network_type (current_network), GNUNET_ATS_print_network_type (new_network));

  if (address->active && !ril_network_is_active (solver, new_network))
  {
    GAS_ril_address_delete (solver, address, GNUNET_NO);
    return;
  }

  agent = ril_get_agent (s, &address->peer, GNUNET_NO);
  if (NULL == agent)
  {
    GNUNET_assert(!ril_network_is_active (solver, current_network));

    GAS_ril_address_add (s, address, new_network);
    return;
  }

  net = ril_get_network (s, current_network);
  net->bw_in_assigned -= agent->bw_in;
  net->bw_out_assigned -= agent->bw_out;

  net = ril_get_network (s, new_network);
  net->bw_in_assigned -= min_bw;
  net->bw_out_assigned -= min_bw;
  address->solver_information = net;
}

/**
 * Give feedback about the current assignment
 *
 * @param solver the solver handle
 * @param application the application
 * @param peer the peer to change the preference for
 * @param scope the time interval for this feedback: [now - scope .. now]
 * @param kind the kind to change the preference
 * @param score the score
 */
void
GAS_ril_address_preference_feedback (void *solver,
    void *application,
    const struct GNUNET_PeerIdentity *peer,
    const struct GNUNET_TIME_Relative scope,
    enum GNUNET_ATS_PreferenceKind kind,
    double score)
{
  LOG(GNUNET_ERROR_TYPE_DEBUG,
      "API_address_preference_feedback() Peer '%s' got a feedback of %+.3f from application %s for "
          "preference %s for %d seconds\n", GNUNET_i2s (peer), "UNKNOWN",
      GNUNET_ATS_print_preference_type (kind), scope.rel_value_us / 1000000);
}

/**
 * Start a bulk operation
 *
 * Since new calculations of the assignment are not triggered by a change of preferences, as it
 * happens in the proportional and the mlp solver, there is no need to block this solver.
 *
 * @param solver the solver
 */
void
GAS_ril_bulk_start (void *solver)
{
  /* nop */
}

/**
 * Bulk operation done
 *
 * Since new calculations of the assignment are not triggered by a change of preferences, as it
 * happens in the proportional and the mlp solver, there is no need to block this solver.
 *
 * @param solver the solver handle
 */
void
GAS_ril_bulk_stop (void *solver)
{
  /* nop */
}

/**
 * Tell solver to notify ATS if the address to use changes for a specific
 * peer using the bandwidth changed callback
 *
 * The solver must only notify about changes for peers with pending address
 * requests!
 *
 * @param solver the solver handle
 * @param peer the identity of the peer
 */
const struct ATS_Address *
GAS_ril_get_preferred_address (void *solver, const struct GNUNET_PeerIdentity *peer)
{
  /*
   * activate agent, return currently chosen address
   */
  struct GAS_RIL_Handle *s = solver;
  struct RIL_Peer_Agent *agent;
  struct RIL_Network *net;

  agent = ril_get_agent (s, peer, GNUNET_YES);

  agent->active = GNUNET_YES;

  if (agent->address_inuse)
  {
    net = agent->address_inuse->solver_information;
    net->bw_in_assigned += agent->bw_in;
    net->bw_out_assigned += agent->bw_out;
  }
  envi_set_active_suggestion (s, agent, agent->address_inuse, agent->bw_in, agent->bw_out,
      GNUNET_YES);

  if (agent->address_inuse)
  {
    LOG(GNUNET_ERROR_TYPE_DEBUG,
        "API_get_preferred_address() Activated agent for peer '%s' with %s address %p\n",
        GNUNET_i2s (peer), agent->address_inuse->plugin, agent->address_inuse->addr);
  }
  else
  {
    LOG(GNUNET_ERROR_TYPE_DEBUG,
        "API_get_preferred_address() Activated agent for peer '%s', but no address available\n",
        GNUNET_i2s (peer));
  }

  return agent->address_inuse;
}

/**
 * Tell solver stop notifying ATS about changes for this peers
 *
 * The solver must only notify about changes for peers with pending address
 * requests!
 *
 * @param solver the solver handle
 * @param peer the peer
 */
void
GAS_ril_stop_get_preferred_address (void *solver, const struct GNUNET_PeerIdentity *peer)
{
  struct GAS_RIL_Handle *s = solver;
  struct RIL_Peer_Agent *agent;
  struct RIL_Network *net;

  agent = ril_get_agent (s, peer, GNUNET_NO);

  if (NULL == agent)
  {
    GNUNET_break(0);
    return;
  }
  if (GNUNET_NO == agent->active)
  {
    GNUNET_break(0);
    return;
  }

  agent->active = GNUNET_NO;
  if (agent->address_inuse)
  {
    net = agent->address_inuse->solver_information;
    net->bw_in_assigned -= agent->bw_in;
    net->bw_out_assigned -= agent->bw_out;
  }
  envi_set_active_suggestion (s, agent, agent->address_inuse, agent->bw_in, agent->bw_out,
      GNUNET_YES);

  LOG(GNUNET_ERROR_TYPE_DEBUG,
      "API_stop_get_preferred_address() Paused agent for peer '%s' with %s address\n",
      GNUNET_i2s (peer), agent->address_inuse->plugin);
}

/* end of libgnunet_plugin_ats_ril.c */
