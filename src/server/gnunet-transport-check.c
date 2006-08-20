/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file server/gnunet-transport-check.c
 * @brief Test for the transports.
 * @author Christian Grothoff
 *
 * This utility can be used to test if a transport mechanism for
 * GNUnet is properly configured.
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_error_loggers.h"
#include "gnunet_protocols.h"
#include "gnunet_transport_service.h"
#include "gnunet_identity_service.h"
#include "gnunet_pingpong_service.h"
#include "gnunet_bootstrap_service.h"
#include "core.h"
#include "connection.h"
#include "handler.h"
#include "startup.h"

#define DEBUG_TRANSPORT_CHECK NO

static struct SEMAPHORE * sem;

static int terminate;

static unsigned long long timeout;

static Transport_ServiceAPI * transport;

static Identity_ServiceAPI * identity;

static Pingpong_ServiceAPI * pingpong;

static Bootstrap_ServiceAPI * bootstrap;

static int ok;

static char * expectedValue;

static unsigned long long expectedSize;

static struct GC_Configuration * cfg;

static struct GE_Context * ectx;

static struct CronManager * cron;

static void semUp(struct SEMAPHORE * sem) {
  terminate = YES;
  SEMAPHORE_UP(sem);
}

static int noiseHandler(const PeerIdentity *peer,
			const MESSAGE_HEADER * msg,
			TSession * s) {
  if ( (ntohs(msg->size) ==
	sizeof(MESSAGE_HEADER) + expectedSize) &&
       (0 == memcmp(expectedValue,
		    &msg[1],
		    expectedSize)) )
    ok = YES;
  SEMAPHORE_UP(sem);
  return OK;
}

/**
 * Test the given transport API.
 */
static void testTAPI(TransportAPI * tapi,
		     void * ctx) {
  int * res = ctx;
  P2P_hello_MESSAGE * helo;
  TSession * tsession;
  unsigned long long repeat;
  unsigned long long total;
  cron_t start;
  cron_t end;
  MESSAGE_HEADER * noise;

  GE_ASSERT(ectx, tapi != NULL);
  if (tapi->protocolNumber == NAT_PROTOCOL_NUMBER) {
    *res = OK;
    return; /* NAT cannot be tested */
  }
  helo = tapi->createhello();
  if (helo == NULL) {
    fprintf(stderr,
	    _("`%s': Could not create hello.\n"),
	    tapi->transName);
    *res = SYSERR;
    return;
  }
  tsession = NULL;
  if (OK != tapi->connect(helo,
			  &tsession)) {
    fprintf(stderr,
	    _("`%s': Could not connect.\n"),
	    tapi->transName);
    *res = SYSERR;
    FREE(helo);
    return;
  }
  FREE(helo);
  if (-1 == GC_get_configuration_value_number(cfg,
					      "TRANSPORT-CHECK",
					      "REPEAT",
					      1,
					      (unsigned long) -1,
					      1,
					      &repeat)) {
    *res = SYSERR;
    FREE(helo);
    return;
  }
  total = repeat;
  sem = SEMAPHORE_CREATE(0);
  start = get_time();
  noise = MALLOC(expectedSize + sizeof(MESSAGE_HEADER));
  noise->type = htons(P2P_PROTO_noise);
  noise->size = htons(expectedSize + sizeof(MESSAGE_HEADER));
  memcpy(&noise[1],
	 expectedValue,
	 expectedSize);
  while (repeat > 0) {
    repeat--;
    ok = NO;
    if (OK != sendPlaintext(tsession,
			    (char*)noise,
			    ntohs(noise->size))) {
      fprintf(stderr,
	      _("`%s': Could not send.\n"),
	      tapi->transName);
      *res = SYSERR;
      tapi->disconnect(tsession);
      SEMAPHORE_DESTROY(sem);
      FREE(noise);
      return;
    }
    cron_add_job(cron,
		 (CronJob)&semUp,
		 timeout,
		 0,
		 sem);
    SEMAPHORE_DOWN(sem, YES);
    cron_suspend(cron, NO);
    cron_del_job(cron,
		 (CronJob)&semUp,
		 0,
		 sem);
    cron_resume_jobs(cron, NO);
    if (ok != YES) {
      FPRINTF(stderr,
	      _("`%s': Did not receive message within %llu ms.\n"),
	      tapi->transName,
	      timeout);
      *res = SYSERR;
      tapi->disconnect(tsession);
      SEMAPHORE_DESTROY(sem);
      FREE(noise);
      return;
    }
  }
  FREE(noise);
  end = get_time();
  if (OK != tapi->disconnect(tsession)) {
    fprintf(stderr,
	    _("`%s': Could not disconnect.\n"),
	    tapi->transName);
    *res = SYSERR;
    SEMAPHORE_DESTROY(sem);
    return;
  }
  SEMAPHORE_DESTROY(sem);
  printf(_("`%s' transport OK.  It took %ums to transmit %llu messages of %llu bytes each.\n"),
	 tapi->transName,
	 (unsigned int) ((end - start)/cronMILLIS),
	 total,
	 expectedSize);
}

static void pingCallback(void * unused) {
  ok = YES;
  SEMAPHORE_UP(sem);
}

static void testPING(const P2P_hello_MESSAGE * xhelo,
		     void * arg) {
  int * stats = arg;
  TSession * tsession;
  P2P_hello_MESSAGE * helo;
  P2P_hello_MESSAGE * myHelo;
  MESSAGE_HEADER * ping;
  char * msg;
  int len;
  PeerIdentity peer;
  unsigned long long verbose;

  stats[0]++; /* one more seen */
  if (NO == transport->isAvailable(ntohs(helo->protocol))) {
    GE_LOG(ectx,
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   _(" Transport %d is not being tested\n"),
	   ntohs(helo->protocol));
    return;
  }
  stats[1]++; /* one more with transport 'available' */
  GC_get_configuration_value_number(cfg,
				    "GNUNET-TRANSPORT-CHECK",
				    "VERBOSE",
				    0, 
				    (unsigned long long) -1,
				    0,
				    &verbose);
  if (verbose > 0) {
    char * str;
    str = transport->heloToString(xhelo);
    fprintf(stderr,
	    _("\nContacting `%s'."),
	    str);
    FREE(str);
  } else
    fprintf(stderr, ".");
  helo = MALLOC(ntohs(xhelo->header.size));
  memcpy(helo, xhelo, ntohs(xhelo->header.size));

  myHelo = transport->createhello(ntohs(xhelo->protocol));
  if (myHelo == NULL) {
    FREE(helo);
    return;
  }
  if (verbose > 0)
    fprintf(stderr, ".");
  tsession = NULL;
  peer = helo->senderIdentity;
  tsession = transport->connect(helo);
  FREE(helo);
  if (tsession == NULL) {
    fprintf(stderr,
	    _(" Connection failed\n"));
    return;
  }
  if (tsession == NULL) {
    GE_BREAK(ectx, 0);
    fprintf(stderr,
	    _(" Connection failed (bug?)\n"));
    return;
  }
  if (verbose > 0)
    fprintf(stderr, ".");

  sem = SEMAPHORE_CREATE(0);

  ping = pingpong->pingUser(&peer,
			    &pingCallback,
			    NULL,
			    YES);
  len = ntohs(ping->size) + ntohs(myHelo->header.size);
  msg = MALLOC(len);
  memcpy(msg,
	 myHelo,
	 ntohs(myHelo->header.size));
  memcpy(&msg[ntohs(myHelo->header.size)],
	 ping,
	 ntohs(ping->size));
  FREE(myHelo);
  FREE(ping);
  /* send ping */
  ok = NO;
  if (OK != sendPlaintext(tsession,
			  msg,
			  len)) {
    fprintf(stderr,
	    "Send failed.\n");
    FREE(msg);
    transport->disconnect(tsession);
    return;
  }
  FREE(msg);
  if (verbose > 0)
    fprintf(stderr, ".");
  /* check: received pong? */
#if DEBUG_TRANSPORT_CHECK
  GE_LOG(ectx, GE_DEBUG | GE_REQUEST | GE_USER,
      "Waiting for PONG\n");
#endif
  terminate = NO;
  cron_add_job(cron,
	       (CronJob)&semUp,
	       timeout,
	       5 * cronSECONDS,
	       sem);
  SEMAPHORE_DOWN(sem, YES);

  if ( (verbose > 0) &&
       (ok != YES) )
    FPRINTF(stderr,
	    _("No reply received within %llums.\n"),
	    timeout);  
  cron_suspend(cron,
	       NO);
  cron_del_job(cron,
	       (CronJob)&semUp,
	       5 * cronSECONDS,
	       sem);
  cron_resume_jobs(cron,
		   NO);
  SEMAPHORE_DESTROY(sem);
  sem = NULL;
  transport->disconnect(tsession);
  if (ok == YES)
    stats[2]++;
}

static int testTerminate(void * arg) {
  return YES;
}

/**
 * All gnunet-transport-check command line options
 */
static struct CommandLineOption gnunettransportcheckOptions[] = {
  COMMAND_LINE_OPTION_CFG_FILE, /* -c */
  COMMAND_LINE_OPTION_HELP(gettext_noop("Tool to test if GNUnet transport services are operational.")), /* -h */
  COMMAND_LINE_OPTION_HOSTNAME, /* -H */
  COMMAND_LINE_OPTION_LOGGING, /* -L */
  { 'p', "ping", NULL, 
    gettext_noop("ping peers from HOSTLISTURL that match transports"), 
    0, &gnunet_getopt_configure_set_option, "TRANSPORT-CHECK:PING=YES" },
#if 0
  { 'P', "Xport", "PORT", 
    gettext_noop(""), 
    0, &gnunet_getopt_configure_set_option, "TRANSPORT-CHECK:PORT" },
#endif
  { 'r', "repeat", "COUNT",
    gettext_noop("send COUNT messages"),
    1, &gnunet_getopt_configure_set_option, "TRANSPORT-CHECK:REPEAT" },
  { 's', "size", "SIZE",
    gettext_noop("send messages with SIZE bytes payload"),
    1, &gnunet_getopt_configure_set_option, "TRANSPORT-CHECK:SIZE" },
  { 't', "transport", "TRANSPORT",
    gettext_noop("specifies which TRANSPORT should be tested"),
    1, &gnunet_getopt_configure_set_option, "GNUNETD:TRANSPORTS" },
  { 'T', "timeout", "MS",
    gettext_noop("specifies after how many MS to time-out"),
    1, &gnunet_getopt_configure_set_option, "TRANSPORT-CHECK:TIMEOUT" },	
  { 'u', "user", "LOGIN",
    gettext_noop("run as user LOGIN"),
    1, &gnunet_getopt_configure_set_option, "GNUNETD:USER" },	
  COMMAND_LINE_OPTION_VERSION(PACKAGE_VERSION), /* -v */
  COMMAND_LINE_OPTION_VERBOSE,
  { 'X', "Xrepeat", "X",
    gettext_noop("repeat each test X times"),
    1, &gnunet_getopt_configure_set_option, "TRANSPORT-CHECK:X-REPEAT" },
  COMMAND_LINE_OPTION_END,
};

int main(int argc, 
	 const char *argv[]) {
  int res;
  unsigned long long Xrepeat;
  char * trans;
  int ping;
  int stats[3];
  int pos;

  ectx = GE_create_context_stderr(NO, 
				  GE_WARNING | GE_ERROR | GE_FATAL |
				  GE_USER | GE_ADMIN | GE_DEVELOPER |
				  GE_IMMEDIATE | GE_BULK);
  GE_setDefaultContext(ectx);
  cfg = GC_create_C_impl();
  GE_ASSERT(ectx, cfg != NULL);
  if (-1 == gnunet_parse_options("gnunetd",
				 ectx,
				 cfg,
				 gnunettransportcheckOptions,
				 (unsigned int) argc,
				 argv)) {
    GC_free(cfg);
    GE_free_context(ectx);
    return -1;  
  }

  if (OK != changeUser(ectx, cfg)) {
    GC_free(cfg);
    GE_free_context(ectx);
    return -1;
  }

  if (-1 == GC_get_configuration_value_number(cfg,
					      "TRANSPORT-CHECK",
					      "SIZE",
					      1,
					      60000,
					      12,
					      &expectedSize)) {
    return 1;
  }
  if (-1 == GC_get_configuration_value_number(cfg,
					      "TRANSPORT-CHECK",
					      "TIMEOUT",
					      1,
					      60000,
					      60 * cronSECONDS,
					      &timeout)) {
    return 1;
  }
  
  expectedValue = MALLOC(expectedSize);
  pos = expectedSize;
  expectedValue[--pos] = '\0';
  while (pos-- > 0)
    expectedValue[pos] = 'A' + (pos % 26);

  trans = NULL;
  if (-1 == GC_get_configuration_value_string(cfg,
					      "GNUNETD",
					      "TRANSPORTS",
					      "udp tcp http",
					      &trans)) 
    return 1;
  GE_ASSERT(ectx, trans != NULL);
  ping = GC_get_configuration_value_yesno(cfg,
					  "TRANSPORT-CHECK",
					  "PING",
					  NO);
  if (! ping)
    printf(_("Testing transport(s) %s\n"),
	   trans);
  else
    printf(_("Available transport(s): %s\n"),
	   trans);
  FREE(trans);
  if (! ping) {
    /* disable blacklists (loopback is often blacklisted)... */
    GC_set_configuration_value_string(cfg,
				      ectx,
				      "TCP",
				      "BLACKLIST",
				      NULL);
    GC_set_configuration_value_string(cfg,
				      ectx,
				      "TCP6",
				      "BLACKLIST",
				      NULL);
    GC_set_configuration_value_string(cfg,
				      ectx,
				      "UDP",
				      "BLACKLIST",
				      NULL);
    GC_set_configuration_value_string(cfg,
				      ectx,
				      "UDP6",
				      "BLACKLIST",
				      NULL);
    GC_set_configuration_value_string(cfg,
				      ectx,
				      "HTTP",
				      "BLACKLIST",
				      NULL);
  }
  cron = cron_create(ectx);
  initCore(ectx, cfg, cron, NULL);
  initConnection(ectx, cfg, NULL, cron);
  registerPlaintextHandler(P2P_PROTO_noise,
			   &noiseHandler);
  enableCoreProcessing();
  identity = requestService("identity");
  transport = requestService("transport");
  pingpong = requestService("pingpong");
  cron_start(cron);

  GC_get_configuration_value_number(cfg,
				    "TRANSPORT-CHECK",
				    "X-REPEAT",
				    1,
				    (unsigned long long) -1,
				    1,
				    &Xrepeat);
  res = OK;
  if (ping) {
    bootstrap = requestService("bootstrap");

    stats[0] = 0;
    stats[1] = 0;
    stats[2] = 0;
    bootstrap->bootstrap(&testPING,
			 &stats[0],
			 &testTerminate,
			 NULL);
    printf(_("%d out of %d peers contacted successfully (%d times transport unavailable).\n"),
	   stats[2],
	   stats[1],
	   stats[0] - stats[1]);
    releaseService(bootstrap);
  } else {
    while (Xrepeat-- > 0)
      transport->forEach(&testTAPI,
			 &res);
  }
  cron_stop(cron);
  releaseService(identity);
  releaseService(transport);
  releaseService(pingpong);
  disableCoreProcessing();
  unregisterPlaintextHandler(P2P_PROTO_noise,
			     &noiseHandler);
  doneConnection();
  doneCore();
  FREE(expectedValue);
  cron_destroy(cron);
  GC_free(cfg);
  GE_free_context(ectx);
 
  if (res == OK)
    return 0;
  else
    return -1;
}


/* end of gnunet-transport-check */
