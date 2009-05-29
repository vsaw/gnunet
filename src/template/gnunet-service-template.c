/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file template/gnunet-service-template.c
 * @brief program that tracks template
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_service_lib.h"

/**
 * Do cleanup here.
 *
 * @param cls closure
 * @param cfg configuration to use
 */
static void
finish (void *cls, struct GNUNET_CONFIGURATION_Handle *cfg)
{
  /* FIXME */
}


/**
 * List of handlers for the messages understood by this
 * service.
 */
static struct GNUNET_SERVER_MessageHandler handlers[] = {
  /* FIXME: add handlers here! */
  {NULL, NULL, 0, 0}
};

/**
 * Process template requests.
 *
 * @param cls closure
 * @param sched scheduler to use
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *sched,
     struct GNUNET_SERVER_Handle *server,
     struct GNUNET_CONFIGURATION_Handle *cfg)
{
  /* FIXME: do setup here */
  GNUNET_SERVER_add_handlers (server, handlers);
}


/**
 * The main function for the template service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc,
                              argv,
                              "template", &run, NULL, &finish, NULL)) ? 0 : 1;
}

/* end of gnunet-service-template.c */
