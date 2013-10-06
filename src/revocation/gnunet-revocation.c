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
 * @file revocation/gnunet-revocation.c
 * @brief tool for revoking public keys
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_revocation_service.h"
#include "gnunet_identity_service.h"


/**
 * Final status code.
 */
static int ret;

/**
 * Was "-p" specified?
 */
static int perform;

/**
 * -f option.
 */
static char *filename;

/**
 * -R option
 */
static char *revoke_ego;

/**
 * -t option.
 */
static char *test_ego;

/**
 * Handle for revocation query.
 */
static struct GNUNET_REVOCATION_Query *q;

/**
 * Handle for revocation.
 */
static struct GNUNET_REVOCATION_Handle *h;

/**
 * Handle for our ego lookup.
 */
static struct GNUNET_IDENTITY_EgoLookup *el;

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Number of matching bits required for revocation.
 */
static unsigned long long matching_bits;


/**
 * Function run if the user aborts with CTRL-C.
 *
 * @param cls closure
 * @param tc scheduler context
 */
static void
do_shutdown (void *cls,
             const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != q)
  {
    GNUNET_REVOCATION_query_cancel (q);
    q = NULL;
  }
  if (NULL != h)
  {
    GNUNET_REVOCATION_revoke_cancel (h);
    h = NULL;
  }
}


/**
 * Print the result from a revocation query.
 *
 * @param cls NULL
 * @param is_valid #GNUNET_YES if the key is still valid, #GNUNET_NO if not, #GNUNET_SYSERR on error
 */
static void
print_query_result (void *cls,
                    int is_valid)
{
  q = NULL;
  switch (is_valid)
  {
  case GNUNET_YES:
    FPRINTF (stdout,
             _("Key `%s' is valid\n"),
             test_ego);
    break;
  case GNUNET_NO:
    FPRINTF (stdout,
             _("Key `%s' has been revoked\n"),
             test_ego);
    break;
  case GNUNET_SYSERR:
    FPRINTF (stdout,
             "%s",
             _("Internal error\n"));
    break;
  default:
    GNUNET_break (0);
    break;
  }
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Print the result from a revocation request.
 *
 * @param cls NULL
 * @param is_valid #GNUNET_YES if the key is still valid, #GNUNET_NO if not, #GNUNET_SYSERR on error
 */
static void
print_revocation_result (void *cls,
                         int is_valid)
{
  h = NULL;
  switch (is_valid)
  {
  case GNUNET_YES:
    FPRINTF (stdout,
             _("Key for ego `%s' is still valid, revocation failed (!)\n"),
             test_ego);
    break;
  case GNUNET_NO:
    FPRINTF (stdout,
             _("Key for ego `%s' has been successfully revoked\n"),
             test_ego);
    break;
  case GNUNET_SYSERR:
    FPRINTF (stdout,
             "%s",
             _("Internal error, key revocation might have failed\n"));
    break;
  default:
    GNUNET_break (0);
    break;
  }
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Data needed to perform a revocation.
 */
struct RevocationData
{
  /**
   * Public key.
   */
  struct GNUNET_CRYPTO_EccPublicSignKey key;

  /**
   * Revocation signature data.
   */
  struct GNUNET_CRYPTO_EccSignature sig;

  /**
   * Proof of work (in NBO).
   */
  uint64_t pow GNUNET_PACKED;
};


/**
 * Perform the revocation.
 */
static void
perform_revocation (const struct RevocationData *rd)
{
  h = GNUNET_REVOCATION_revoke (cfg,
                                &rd->key,
                                &rd->sig,
                                rd->pow,
                                &print_revocation_result,
                                NULL);
}


/**
 * Perform the proof-of-work calculation.
 *
 * @param cls the `struct RevocationData`
 * @param tc scheduler context
 */
static void
calculate_pow (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct RevocationData *rd = cls;

  if ( (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason)) ||
       (0 == (rd->pow % 128) ) )
  {
    if (0 == (rd->pow % 128 * 1024))
    {
      if (0 == (rd->pow % (1024 * 128 * 80)))
        fprintf (stderr, "\n");
      fprintf (stderr, ".");
    }
    if ( (NULL != filename) &&
         (sizeof (struct RevocationData) ==
          GNUNET_DISK_fn_write (filename,
                                &rd,
                                sizeof (rd),
                                GNUNET_DISK_PERM_USER_READ |
                                GNUNET_DISK_PERM_USER_WRITE)) )
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                                "write",
                                filename);
  }
  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
  {
    GNUNET_free (rd);
    return;
  }
  rd->pow++;
  if (GNUNET_OK ==
      GNUNET_REVOCATION_check_pow (&rd->key,
                                   rd->pow,
                                   (unsigned int) matching_bits))
  {
    if ( (NULL != filename) &&
         (sizeof (struct RevocationData) ==
          GNUNET_DISK_fn_write (filename,
                                &rd,
                                sizeof (rd),
                                GNUNET_DISK_PERM_USER_READ |
                                GNUNET_DISK_PERM_USER_WRITE)) )
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                                "write",
                                filename);
    if (perform)
      perform_revocation (rd);
    else
    {
      FPRINTF (stderr,
               _("Revocation certificate for `%s' stored in `%s'\n"),
               revoke_ego,
               filename);
      GNUNET_SCHEDULER_shutdown ();
    }
    GNUNET_free (rd);
  }
  GNUNET_SCHEDULER_add_now (&calculate_pow,
                            rd);
}


/**
 * Function called with the result from the ego lookup.
 *
 * @param cls closure
 * @param ego the ego, NULL if not found
 */
static void
ego_callback (void *cls,
              const struct GNUNET_IDENTITY_Ego *ego)
{
  struct RevocationData *rd;
  struct GNUNET_CRYPTO_EccPublicSignKey key;

  el = NULL;
  if (NULL == ego)
  {
    FPRINTF (stdout,
             _("Ego `%s' not found.\n"),
             test_ego);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_IDENTITY_ego_get_public_key (ego,
                                      &key);
  rd = GNUNET_new (struct RevocationData);
  if ( (NULL != filename) &&
       (GNUNET_YES ==
        GNUNET_DISK_file_test (filename)) &&
       (sizeof (struct RevocationData) ==
        GNUNET_DISK_fn_read (filename,
                             &rd,
                             sizeof (rd))) )
  {
    if (0 != memcmp (&rd->key,
                     &key,
                     sizeof (struct GNUNET_CRYPTO_EccPublicSignKey)))
    {
      fprintf (stderr,
               _("Error: revocation certificate in `%s' is not for `%s'\n"),
               filename,
               revoke_ego);
      GNUNET_free (rd);
      return;
    }
  }
  else
  {
    GNUNET_REVOCATION_sign_revocation (GNUNET_IDENTITY_ego_get_private_key (ego),
                                       &rd->sig);
    rd->key = key;
  }
  if (GNUNET_YES ==
      GNUNET_REVOCATION_check_pow (&key,
                                   rd->pow,
                                   (unsigned int) matching_bits))
  {
    FPRINTF (stderr,
             "%s",
             _("Revocation certificate ready, initiating revocation\n"));
    perform_revocation (rd);
    GNUNET_free (rd);
    return;
  }
  FPRINTF (stderr,
           "%s",
           _("Revocation certificate not ready, calculating proof of work\n"));
  GNUNET_SCHEDULER_add_now (&calculate_pow,
                            rd);
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  struct GNUNET_CRYPTO_EccPublicSignKey pk;
  struct RevocationData rd;

  cfg = c;
  if (NULL != test_ego)
  {
    if (GNUNET_OK !=
        GNUNET_CRYPTO_ecc_public_sign_key_from_string (test_ego,
                                                       strlen (test_ego),
                                                       &pk))
    {
      FPRINTF (stderr,
               _("Public key `%s' malformed\n"),
               test_ego);
      return;
    }
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                  &do_shutdown,
                                  NULL);
    q = GNUNET_REVOCATION_query (cfg,
                                 &pk,
                                 &print_query_result,
                                 NULL);
    if (NULL != revoke_ego)
      FPRINTF (stderr,
               "%s",
               _("Testing and revoking at the same time is not allowed, only executing test.\n"));
    return;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg,
                                             "REVOCATION",
                                             "WORKBITS",
                                             &matching_bits))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "REVOCATION",
                               "WORKBITS");
    return;
  }
  if (NULL != revoke_ego)
  {
    /* main code here */
    el = GNUNET_IDENTITY_ego_lookup (cfg,
                                     revoke_ego,
                                     &ego_callback,
                                     NULL);
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                  &do_shutdown,
                                  NULL);
    return;
  }
  if ( (NULL != filename) &&
       (perform) )
  {
    if (sizeof (rd) !=
        GNUNET_DISK_fn_read (filename,
                             &rd,
                             sizeof (rd)))
    {
      fprintf (stderr,
               _("Failed to read revocation certificate from `%s'\n"),
               filename);
      return;
    }
    perform_revocation (&rd);
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                  &do_shutdown,
                                  NULL);
    return;
  }
  FPRINTF (stderr,
           "%s",
           _("No action specified. Nothing to do.\n"));
}


/**
 * The main function of gnunet-revocation.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'f', "filename", "NAME",
     gettext_noop ("use NAME for the name of the revocation file"),
     1, &GNUNET_GETOPT_set_string, &filename},
    {'R', "revoke", "NAME",
     gettext_noop ("revoke the private key associated with the ego NAME "),
     1, &GNUNET_GETOPT_set_string, &revoke_ego},
    {'p', "perform", NULL,
     gettext_noop ("actually perform the revocation revocation file, otherwise we just do the precomputation"),
     0, &GNUNET_GETOPT_set_one, &perform},
    {'t', "test", "KEY",
     gettext_noop ("test if the public key KEY has been revoked"),
     1, &GNUNET_GETOPT_set_string, &test_ego},
    GNUNET_GETOPT_OPTION_END
  };
  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  ret = (GNUNET_OK ==
	 GNUNET_PROGRAM_run (argc, argv, "gnunet-revocation",
			     gettext_noop ("help text"), options, &run,
			     NULL)) ? ret : 1;
  GNUNET_free ((void*) argv);
  return ret;
}

/* end of gnunet-revocation.c */
