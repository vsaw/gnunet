/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2006, 2007, 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file fs/gnunet-pseudonym.c
 * @brief manage GNUnet namespaces / pseudonyms
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_fs_service.h"

/**
 * -a optiton.
 */
static unsigned int anonymity;

/**
 * -A option.
 */
static int start_automate;

/**
 * -e option
 */
static int stop_automate;

/**
 * -C option
 */
static char *create_ns;

/**
 * -D option
 */
static char *delete_ns;

/**
 * -k option
 */
static struct GNUNET_FS_Uri *ksk_uri;

/**
 * -l option.
 */
static int print_local_only;

/**
 * -m option.
 */
static struct GNUNET_CONTAINER_MetaData *adv_metadata;

/**
 * -n option.
 */
static int no_advertising;

/**
 * -p option.
 */
static unsigned int priority = 365;

/**
 * -q option given.
 */
static int no_remote_printing; 

/**
 * -r option.
 */
static char *root_identifier;

/**
 * -s option.
 */
static char *rating_change;

/**
 * Handle to fs service.
 */
static struct GNUNET_FS_Handle *h;

/**
 * Namespace we are looking at.
 */
static struct GNUNET_FS_Namespace *ns;


static int ret;

static void* 
progress_cb (void *cls,
	     const struct GNUNET_FS_ProgressInfo *info)
{
  return NULL;
}


static void
ns_printer (void *cls,
	    const char *name,
	    const GNUNET_HashCode *id)
{
  struct GNUNET_CRYPTO_HashAsciiEncoded enc;

  GNUNET_CRYPTO_hash_to_enc (id, &enc);
  fprintf (stdout, 
	   "%s (%s)\n",
	   name,
	   (const char*) &enc);
}


static void
post_advertising (void *cls,
		  const struct GNUNET_FS_Uri *uri,
		  const char *emsg)
{
  if (emsg != NULL)
    {
      fprintf (stderr, "%s", emsg);
      ret = 1;
    }
  if (ns != NULL)
    {
      if (GNUNET_OK !=
	  GNUNET_FS_namespace_delete (ns,
				      GNUNET_NO))
	ret = 1;
    }
  if (0 != stop_automate)
    {
      GNUNET_break (0); // FIXME: not implemented
    }
  if (0 != start_automate)
    {
      GNUNET_break (0); // FIXME: not implemented
    }
  if (NULL != rating_change)
    {
      GNUNET_break (0); // FIXME: not implemented
    }
  if (0 != print_local_only)
    {
      GNUNET_FS_namespace_list (h,
				&ns_printer, 
				NULL);
    }  
  else if (0 == no_remote_printing)
    {
      GNUNET_break (0); // FIXME: not implemented
    }
  /* FIXME: is this OK here, or do we need
     for completion of previous requests? */
  GNUNET_FS_stop (h);
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param sched the scheduler to use
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *sched,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_FS_Uri *ns_uri;
  struct GNUNET_TIME_Absolute expiration;

  h = GNUNET_FS_start (sched,
		       cfg,
		       "gnunet-pseudonym",
		       &progress_cb,
		       NULL,
		       GNUNET_FS_FLAGS_NONE);
  if (NULL != delete_ns)
    {
      ns = GNUNET_FS_namespace_create (h, delete_ns);
      if (ns == NULL)
	{
	  ret = 1;
	}
      else
	{
	  if (GNUNET_OK !=
	      GNUNET_FS_namespace_delete (ns,
					  GNUNET_YES))
	    ret = 1;
	  ns = NULL;
	}
    }
  if (NULL != create_ns)
    {
      ns = GNUNET_FS_namespace_create (h, create_ns);
      if (ns == NULL)
	{
	  ret = 1;
	}
      else
	{
	  if (0 == no_advertising)
	    {
	      GNUNET_break (0); // FIXME: not implemented
	      ns_uri = NULL; // FIXME!!
	      expiration = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_YEARS);
	      GNUNET_FS_publish_ksk (h,
				     ksk_uri,
				     adv_metadata,
				     ns_uri,
				     expiration,
				     anonymity,
				     priority,
				     GNUNET_FS_PUBLISH_OPTION_NONE,
				     &post_advertising,
				     NULL);
	      return;
	    }
	}
    }
  post_advertising (NULL, NULL, NULL);
}

/**
 * gnunet-pseudonym command line options
 */
static struct GNUNET_GETOPT_CommandLineOption options[] = {
  {'a', "anonymity", "LEVEL",
   gettext_noop ("set the desired LEVEL of sender-anonymity"),
   1, &GNUNET_GETOPT_set_uint, &anonymity},
  {'A', "automate", NULL,
   gettext_noop ("start a collection"),
   0, &GNUNET_GETOPT_set_one, &start_automate},
  {'C', "create", "NAME",
   gettext_noop
   ("create or advertise namespace NAME"),
   1, &GNUNET_GETOPT_set_string, &create_ns},
  {'D', "delete", "NAME",
   gettext_noop
   ("delete namespace NAME "),
   1, &GNUNET_GETOPT_set_string, &delete_ns},
  {'e', "end", NULL,
   gettext_noop ("end current collection"),
   0, &GNUNET_GETOPT_set_one, &stop_automate},
  {'k', "keyword", "VALUE",
  gettext_noop
   ("add an additional keyword for the advertisment"
    " (this option can be specified multiple times)"),
   1, &GNUNET_FS_getopt_set_keywords, &ksk_uri},
  {'l', "local-only", NULL,
   gettext_noop ("print names of local namespaces"),
   0, &GNUNET_GETOPT_set_one, &print_local_only},
  {'m', "meta", "TYPE:VALUE",
   gettext_noop ("set the meta-data for the given TYPE to the given VALUE"),
   1, &GNUNET_FS_getopt_set_metadata, &adv_metadata},
  {'n', "no-advertisement", NULL,
   gettext_noop ("do not create an advertisement"),
   0, &GNUNET_GETOPT_set_one, &no_advertising},
  {'p', "priority", "PRIORITY",
   gettext_noop ("use the given PRIORITY for the advertisments"),
   1, &GNUNET_GETOPT_set_uint, &priority},
  {'q', "quiet", NULL,
   gettext_noop ("do not print names of remote namespaces"),
   0, &GNUNET_GETOPT_set_one, &no_remote_printing},
  {'r', "root", "ID",
   gettext_noop
   ("specify ID of the root of the namespace"),
   1, &GNUNET_GETOPT_set_string, &root_identifier},
  {'s', "set-rating", "ID:VALUE",
   gettext_noop
   ("change rating of namespace ID by VALUE"),
   1, &GNUNET_GETOPT_set_string, &rating_change},
  GNUNET_GETOPT_OPTION_END
};


/**
 * The main function to inspect GNUnet directories.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc,
                              argv,
                              "gnunet-pseudonym",
                              gettext_noop
                              ("Manage GNUnet pseudonyms."),
                              options, &run, NULL)) ? ret : 1;
}

/* end of gnunet-pseudonym.c */
