/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file transport/test_transport_api_disconnect.c
 * @brief base test case for transport implementations
 *
 * This test case serves as a base for tcp, udp, and udp-nat
 * transport test cases.  Based on the executable being run
 * the correct test case will be performed.  Conservation of
 * C code apparently.
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_hello_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_transport_service.h"
#include "transport.h"
#include "transport-testing.h"

#define VERBOSE GNUNET_NO

#define VERBOSE_ARM GNUNET_NO

#define START_ARM GNUNET_YES

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 300)

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT_TRANSMIT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

#define MTYPE 12345

#define ITERATIONS 50

static struct PeerContext p1;

static struct PeerContext p2;

static int ok;

static int peers_connected = 0;
static int counter;
static int msgs_recv;

static GNUNET_SCHEDULER_TaskIdentifier die_task;

static GNUNET_SCHEDULER_TaskIdentifier tct;

struct GNUNET_TRANSPORT_TransmitHandle *th;

#if VERBOSE
#define OKPP do { ok++; fprintf (stderr, "Now at stage %u at %s:%u\n", ok, __FILE__, __LINE__); } while (0)
#else
#define OKPP do { ok++; } while (0)
#endif


static void
peers_connect ();

static void
end ()
{
  if (GNUNET_SCHEDULER_NO_TASK != die_task)
    GNUNET_SCHEDULER_cancel (die_task);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting from transports!\n");
  if (th != NULL)
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
  th = NULL;

  if (p1.th != NULL)
    GNUNET_TRANSPORT_disconnect (p1.th);

  if (p2.th != NULL)
    GNUNET_TRANSPORT_disconnect (p2.th);
  die_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transports disconnected, returning success!\n");
  ok = 0;
}

static void
stop_arm (struct PeerContext *p)
{
#if START_ARM
  if (NULL != p->arm_proc)
  {
    if (0 != GNUNET_OS_process_kill (p->arm_proc, SIGTERM))
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
    GNUNET_OS_process_wait (p->arm_proc);
    GNUNET_OS_process_close (p->arm_proc);
    p->arm_proc = NULL;
  }
#endif
  GNUNET_CONFIGURATION_destroy (p->cfg);
}




static void
exchange_hello_last (void *cls, const struct GNUNET_MessageHeader *message)
{
  struct PeerContext *me = cls;

  GNUNET_assert (message != NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Exchanging HELLO of size %d with peer (%s)!\n",
              (int) GNUNET_HELLO_size ((const struct GNUNET_HELLO_Message *)
                                       message), GNUNET_i2s (&me->id));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *)
                                      message, &me->id));
  GNUNET_TRANSPORT_offer_hello (p1.th, message, NULL, NULL);
}


static void
exchange_hello (void *cls, const struct GNUNET_MessageHeader *message)
{
  struct PeerContext *me = cls;

  GNUNET_assert (message != NULL);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *)
                                      message, &me->id));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Exchanging HELLO of size %d from peer %s!\n",
              (int) GNUNET_HELLO_size ((const struct GNUNET_HELLO_Message *)
                                       message), GNUNET_i2s (&me->id));
  GNUNET_TRANSPORT_offer_hello (p2.th, message, NULL, NULL);
}


static void
end_badly ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting from transports!\n");
  GNUNET_break (0);

  if (th != NULL)
  {
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
    th = NULL;
  }
  else
  {
    GNUNET_TRANSPORT_get_hello_cancel (p2.th, &exchange_hello_last, &p2);
    GNUNET_TRANSPORT_get_hello_cancel (p1.th, &exchange_hello, &p1);
  }

  GNUNET_TRANSPORT_disconnect (p1.th);
  GNUNET_TRANSPORT_disconnect (p2.th);
  if (GNUNET_SCHEDULER_NO_TASK != tct)
  {
    GNUNET_SCHEDULER_cancel (tct);
    tct = GNUNET_SCHEDULER_NO_TASK;
  }
  ok = 1;
}


static void
notify_receive (void *cls, const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_MessageHeader *message,
                const struct GNUNET_TRANSPORT_ATS_Information *ats,
                uint32_t ats_count)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received message of type %d from peer %s!\n",
              ntohs (message->type), GNUNET_i2s (peer));
  OKPP;
  GNUNET_assert (MTYPE == ntohs (message->type));
  GNUNET_assert (sizeof (struct GNUNET_MessageHeader) == ntohs (message->size));

  msgs_recv++;
}

static void
peers_disconnect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

static size_t
notify_ready (void *cls, size_t size, void *buf)
{
  struct PeerContext *p = cls;
  struct GNUNET_MessageHeader *hdr;

  th = NULL;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting message with %u bytes to peer %s\n",
              sizeof (struct GNUNET_MessageHeader), GNUNET_i2s (&p->id));
  GNUNET_assert (size >= 256);
  OKPP;
  if (buf != NULL)
  {
    hdr = buf;
    hdr->size = htons (sizeof (struct GNUNET_MessageHeader));
    hdr->type = htons (MTYPE);
  }

  GNUNET_SCHEDULER_add_now (&peers_disconnect, NULL);

  return sizeof (struct GNUNET_MessageHeader);
}


static void
notify_connect (void *cls, const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_TRANSPORT_ATS_Information *ats,
                uint32_t ats_count)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer `%4s' connected to us (%p)!\n",
              GNUNET_i2s (peer), cls);
  peers_connected++;
  if (cls == &p1)
  {
    GNUNET_assert (ok >= 2);
    OKPP;
    OKPP;
    if (GNUNET_SCHEDULER_NO_TASK != die_task)
      GNUNET_SCHEDULER_cancel (die_task);
    if (GNUNET_SCHEDULER_NO_TASK != tct)
      GNUNET_SCHEDULER_cancel (tct);
    tct = GNUNET_SCHEDULER_NO_TASK;

    die_task =
        GNUNET_SCHEDULER_add_delayed (TIMEOUT_TRANSMIT, &end_badly, NULL);
    th = GNUNET_TRANSPORT_notify_transmit_ready (p1.th, &p2.id, 256, 0, TIMEOUT,
                                                 &notify_ready, &p1);
  }
}


static void
notify_disconnect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer `%4s' disconnected (%p)!\n",
              GNUNET_i2s (peer), cls);
  peers_connected--;
}


static void
setup_peer (struct PeerContext *p, const char *cfgname)
{
  p->cfg = GNUNET_CONFIGURATION_create ();

  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (p->cfg, cfgname));
  if (GNUNET_CONFIGURATION_have_value (p->cfg, "PATHS", "SERVICEHOME"))
    GNUNET_CONFIGURATION_get_value_string (p->cfg, "PATHS", "SERVICEHOME",
                                           &p->servicehome);
  if (NULL != p->servicehome)
    GNUNET_DISK_directory_remove (p->servicehome);

#if START_ARM
  p->arm_proc =
      GNUNET_OS_start_process (NULL, NULL, "gnunet-service-arm",
                               "gnunet-service-arm",
#if VERBOSE_ARM
                               "-L", "DEBUG",
#endif
                               "-c", cfgname, NULL);
#endif

}


static void
try_connect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Asking peers to connect...\n");
  /* FIXME: 'pX.id' may still be all-zeros here... */
  GNUNET_TRANSPORT_try_connect (p2.th, &p1.id);
  GNUNET_TRANSPORT_try_connect (p1.th, &p2.id);
  tct =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &try_connect,
                                    NULL);
}


static void
peers_disconnect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;

  //while (peers_connected > 0);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting from Transport \n");

  GNUNET_TRANSPORT_get_hello_cancel (p2.th, &exchange_hello_last, &p2);
  GNUNET_TRANSPORT_get_hello_cancel (p1.th, &exchange_hello, &p1);

  GNUNET_TRANSPORT_disconnect (p1.th);
  p1.th = NULL;

  GNUNET_TRANSPORT_disconnect (p2.th);
  p2.th = NULL;

  while (peers_connected > 0) ;

  if (counter < ITERATIONS)
  {
    if ((counter % (ITERATIONS / 10)) == 0)
      fprintf (stderr, "%u%%..", (counter / (ITERATIONS / 10)) * 10);
    peers_connect ();
  }
  else
  {
    fprintf (stderr, "100%%\n");
    end ();
  }
}

static void
peers_connect ()
{
  counter++;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Iteration %i of %i\n", counter,
              ITERATIONS);

  GNUNET_assert (p1.th == NULL);
  p1.th =
      GNUNET_TRANSPORT_connect (p1.cfg, NULL, &p1, &notify_receive,
                                &notify_connect, &notify_disconnect);

  GNUNET_assert (p2.th == NULL);
  p2.th =
      GNUNET_TRANSPORT_connect (p2.cfg, NULL, &p2, &notify_receive,
                                &notify_connect, &notify_disconnect);

  GNUNET_assert (p1.th != NULL);
  GNUNET_assert (p2.th != NULL);

  GNUNET_TRANSPORT_get_hello (p1.th, &exchange_hello, &p1);
  GNUNET_TRANSPORT_get_hello (p2.th, &exchange_hello_last, &p2);
  tct = GNUNET_SCHEDULER_add_now (&try_connect, NULL);
}

static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_assert (ok == 1);
  OKPP;
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);

  setup_peer (&p1, "test_transport_api_tcp_peer1.conf");
  setup_peer (&p2, "test_transport_api_tcp_peer2.conf");

  peers_connect ();
}

static int
check ()
{
  static char *const argv[] = { "test-transport-api",
    "-c",
    "test_transport_api_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

#if WRITECONFIG
  setTransportOptions ("test_transport_api_data.conf");
#endif
  ok = 1;
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv,
                      "test-transport-api", "nohelp", options, &run, &ok);
  stop_arm (&p1);
  stop_arm (&p2);

  if (p1.servicehome != NULL)
  {
    GNUNET_DISK_directory_remove (p1.servicehome);
    GNUNET_free (p1.servicehome);
  }
  if (p2.servicehome != NULL)
  {
    GNUNET_DISK_directory_remove (p2.servicehome);
    GNUNET_free (p2.servicehome);
  }
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test_transport_api_disconnect",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);

  ret = check ();
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Messages received:  %i\n", msgs_recv);
  return ret;
}

/* end of test_transport_api_disconnect.c */
