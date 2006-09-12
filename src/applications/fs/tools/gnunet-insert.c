/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/tools/gnunet-insert.c
 * @brief Tool to insert or index files into GNUnet's FS.
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author James Blackwell
 * @author Igor Wronsky
 */

#include "platform.h"
#include "gnunet_fsui_lib.h"
#include "gnunet_namespace_lib.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_error_loggers.h"
#include "gnunet_util_crypto.h"

/* hmm. Man says time.h, but that doesn't yield the
   prototype.  Strange... */
extern char *strptime(const char *s,
		      const char *format,
		      struct tm *tm);

static struct SEMAPHORE * exitSignal;

static int errorCode = 0;

static struct GC_Configuration * cfg;

static struct GE_Context * ectx;

static struct FSUI_Context * ctx;

static struct FSUI_UploadList * ul;

static cron_t start_time;

/* ************ config options ******** */

static char * cfgFilename;

static struct ECRS_MetaData * meta;

static struct ECRS_URI * topKeywords;

static struct ECRS_URI * gloKeywords;

static struct ECRS_MetaData * meta;

static unsigned int anonymity = 1;

static unsigned int priority = 365;

static unsigned int interval = 0;

static char * next_id;

static char * this_id;

static char * prev_id;

static char * creation_time;

static char * pseudonym;

static int do_insert;

static int do_direct_references;

static int do_copy;

static int is_sporadic;

static int extract_only;

static int do_disable_creation_time;

static void convertId(const char * s,
		      HashCode512 * id) {
  if ( (s != NULL) &&
       (enc2hash(s,
		 id) == SYSERR) )
    hash(s,
	 strlen(s),
	 id);
}

/**
 * We're done with the upload of the file, do the
 * post-processing.
 */
static void postProcess(const struct ECRS_URI * uri) {
  char * pname;
  HashCode512 prevId;
  HashCode512 thisId;
  HashCode512 nextId;
  struct ECRS_URI * nsuri;
  char * us;

  if (pseudonym == NULL)
    return;
  convertId(next_id, &nextId);
  convertId(this_id, &thisId);
  convertId(prev_id, &prevId);
  nsuri = NS_addToNamespace(ectx,
			    cfg,
			    anonymity,
			    priority,
			    1024, /* FIXME: expiration */
			    pname,
			    (TIME_T) interval,
			    prev_id == NULL ? NULL : &prevId,
			    this_id == NULL ? NULL : &thisId,
			    next_id == NULL ? NULL : &nextId,
			    uri,
			    meta);
  if (nsuri != NULL) {
    us = ECRS_uriToString(nsuri);
    ECRS_freeUri(nsuri);
    printf(_("Created entry `%s' in namespace `%s'\n"),
	   us,
	   pname);
    FREE(us);
  } else {
    printf(_("Failed to add entry to namespace `%s' (does it exist?)\n"),
	   pname);
  }
  FREE(pname);
}

/**
 * Print progess message.
 */
static void * printstatus(void * ctx,
			  const FSUI_Event * event) {
  unsigned long long * verboselevel = ctx;
  unsigned long long delta;
  char * fstring;

  switch(event->type) {
  case FSUI_upload_progress:
    if (*verboselevel) {
      char * ret;

      delta = event->data.UploadProgress.eta - get_time();
      ret = string_get_fancy_time_interval(delta);
      PRINTF(_("%16llu of %16llu bytes inserted "
	       "(estimating %6s to completion) - %s\n"),
	     event->data.UploadProgress.completed,
	     event->data.UploadProgress.total,
	     ret,
	     event->data.UploadProgress.filename);
      FREE(ret);
    }
    break;
  case FSUI_upload_complete:
    if (*verboselevel) {
      delta = get_time() - start_time;
      PRINTF(_("Upload of `%s' complete, "
	       "%llu bytes took %llu seconds (%8.3f KiB/s).\n"),
	     event->data.UploadComplete.filename,
	     event->data.UploadComplete.total,
	     delta / cronSECONDS,
	     (delta == 0)
	     ? (double) (-1.0)
	     : (double) (event->data.UploadComplete.total
			 / 1024.0 * cronSECONDS / delta));
    }
    fstring = ECRS_uriToString(event->data.UploadComplete.uri);	
    printf(_("File `%s' has URI: %s\n"),
	   event->data.UploadComplete.filename,
	   fstring);
    FREE(fstring);
    if (ul == event->data.UploadComplete.uc.pos) {
      postProcess(event->data.UploadComplete.uri);
      if (exitSignal != NULL)
	SEMAPHORE_UP(exitSignal);
    }
    break;
  case FSUI_upload_aborted:
    printf(_("\nUpload aborted.\n"));
    errorCode = 1;
    if (exitSignal != NULL)
      SEMAPHORE_UP(exitSignal); /* always exit main? */
    break;
  case FSUI_upload_error:
    printf(_("\nError uploading file: %s\n"),
	   event->data.UploadError.message);
    errorCode = 1;
    if (exitSignal != NULL)
      SEMAPHORE_UP(exitSignal); /* always exit main? */
    break;
  default:
    GE_BREAK(ectx, 0);
    break;
  }
  return NULL;
}

/**
 * All gnunet-insert command line options
 */
static struct CommandLineOption gnunetinsertOptions[] = {
  { 'a', "anonymity", "LEVEL",
    gettext_noop("set the desired LEVEL of sender-anonymity"),
    1, &gnunet_getopt_configure_set_uint, &anonymity }, 
  COMMAND_LINE_OPTION_CFG_FILE(&cfgFilename), /* -c */
  { 'C', "copy", NULL,
    gettext_noop("even if gnunetd is running on the local machine, force the"
		 " creation of a copy instead of making a link to the GNUnet share directory"),
    0, &gnunet_getopt_configure_set_one, &do_copy }, 
  { 'd', "disable-creation-time", NULL,
    gettext_noop("disable adding the creation time to the metadata of the uploaded file"),
    0, &gnunet_getopt_configure_set_one, &do_disable_creation_time }, 
  { 'D', "direct", NULL,
    gettext_noop("use libextractor to add additional direct references to directory entries"),
    0, &gnunet_getopt_configure_set_one, &do_direct_references }, 
  { 'e', "extract", NULL,
    gettext_noop("print list of extracted keywords that would be used, but do not perform upload"),
    0, &gnunet_getopt_configure_set_one, &extract_only },  
  COMMAND_LINE_OPTION_HELP(gettext_noop("Make files available to GNUnet for sharing.")), /* -h */
  COMMAND_LINE_OPTION_HOSTNAME, /* -H */
  { 'i', "interval", "SECONDS",
    gettext_noop("set interval for availability of updates to SECONDS"
		 " (for namespace insertions only)"),
    1, &gnunet_getopt_configure_set_uint, &interval },  
  { 'k', "key", "KEYWORD",
    gettext_noop("add an additional keyword for the top-level file or directory"
		 " (this option can be specified multiple times)"),
    1, &gnunet_getopt_configure_set_keywords, &topKeywords },    
  { 'K', "global-key", "KEYWORD",
    gettext_noop("add an additional keyword for all files and directories"
		 " (this option can be specified multiple times)"),
    1, &gnunet_getopt_configure_set_keywords, &gloKeywords },    
  COMMAND_LINE_OPTION_LOGGING, /* -L */  
  { 'm', "meta", "TYPE:VALUE",
    gettext_noop("set the meta-data for the given TYPE to the given VALUE"),
    1, &gnunet_getopt_configure_set_metadata, &meta },
  { 'n', "noindex", NULL,
    gettext_noop("do not index, perform full insertion (stores entire "
		 "file in encrypted form in GNUnet database)"),
    0, &gnunet_getopt_configure_set_one, &do_insert },  
  { 'N', "next", "ID",
    gettext_noop("specify ID of an updated version to be published in the future"
		 " (for namespace insertions only)"),
    1, &gnunet_getopt_configure_set_string, &next_id },  
  { 'p', "priority", "PRIORITY",
    gettext_noop("specify the priority of the content"),
    1, &gnunet_getopt_configure_set_uint, &priority }, 
  { 'P', "pseudonym", "NAME",
    gettext_noop("publish the files under the pseudonym NAME (place file into namespace)"),
    1, &gnunet_getopt_configure_set_string, &pseudonym },  
  { 'S', "sporadic", NULL,
    gettext_noop("specifies this as an aperiodic but updated publication"
		 " (for namespace insertions only)"),
    0, &gnunet_getopt_configure_set_one, &is_sporadic },
  { 't', "this", "ID",
    gettext_noop("set the ID of this version of the publication"
		 " (for namespace insertions only)"),
    1, &gnunet_getopt_configure_set_string, &this_id },  
  { 'T', "time", "TIME",
    gettext_noop("specify creation time for SBlock (see man-page for format)"),
    1, &gnunet_getopt_configure_set_string, &creation_time },  
  { 'u', "update", "ID",
    gettext_noop("ID of the previous version of the content"
		 " (for namespace update only)"),
    1, &gnunet_getopt_configure_set_string, &prev_id },  
  COMMAND_LINE_OPTION_VERSION(PACKAGE_VERSION), /* -v */
  COMMAND_LINE_OPTION_VERBOSE,
  COMMAND_LINE_OPTION_END,
};

/**
 * The main function to insert files into GNUnet.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return return 0 for ok, -1 on error
 */
int main(int argc, 
	 const char ** argv) {
  const char * filename;
  int i;
  char * tmp;
  unsigned long long verbose;
  struct SEMAPHORE * es;

  ectx = GE_create_context_stderr(NO, 
				  GE_WARNING | GE_ERROR | GE_FATAL |
				  GE_USER | GE_ADMIN | GE_DEVELOPER |
				  GE_IMMEDIATE | GE_BULK);
  GE_setDefaultContext(ectx);
  os_init(ectx);
  cfg = GC_create_C_impl();
  GE_ASSERT(ectx, cfg != NULL);
  i = gnunet_parse_options("gnunet-insert [OPTIONS] FILENAME",
			   ectx,
			   cfg,
			   gnunetinsertOptions,
			   (unsigned int) argc,
			   argv);
  if (i == SYSERR) {
    errorCode = -1;
    goto quit;  
  }
  if (i != argc - 1) {
    printf(_("You must specify one and only one filename for insertion.\n"));
    errorCode = -1;
    goto quit;
  }
  filename = argv[i];

  if (extract_only) {
    EXTRACTOR_ExtractorList * l;
    char * ex;
    EXTRACTOR_KeywordList * list;
	    
    l = EXTRACTOR_loadDefaultLibraries();
    GC_get_configuration_value_string(cfg,
				      "FS",
				      "EXTRACTORS",
				      NULL,
				      &ex);
    if (ex != NULL) {
      l = EXTRACTOR_loadConfigLibraries(l,
					ex);
      FREE(ex);
    }
    list
      = EXTRACTOR_getKeywords(l, filename);
    printf(_("Keywords for file `%s':\n"),
	   filename);
    EXTRACTOR_printKeywords(stdout,
			    list);
    EXTRACTOR_freeKeywords(list);
    EXTRACTOR_removeAll(l);
    ECRS_freeMetaData(meta);

    errorCode = 0;
    goto quit; 
  }

  
  GC_get_configuration_value_number(cfg,
				    "GNUNET",
				    "VERBOSE",
				    0,
				    9999,
				    0,
				    &verbose);
  /* check arguments */
  if (pseudonym != NULL) {
    if (OK != ECRS_testNamespaceExists(ectx,
				       cfg,
				       pseudonym,
				       NULL)) {
      printf(_("Could not access namespace `%s' (does not exist?).\n"),
	     pseudonym);
      errorCode = -1;
      goto quit;
    }
    if (creation_time != NULL) {
      struct tm t;
      if ((NULL == strptime(creation_time,
#if ENABLE_NLS
			    nl_langinfo(D_T_FMT),
#else
			    "%Y-%m-%d",
#endif
			    &t))) {
	GE_LOG_STRERROR(ectx,
			GE_FATAL | GE_USER | GE_IMMEDIATE, 
			"strptime");
	printf(_("Parsing time failed. Use `%s' format.\n"),
#if ENABLE_NLS
	       nl_langinfo(D_T_FMT)
#else
	       "%Y-%m-%d"
#endif
	       );
  errorCode = -1;
	goto quit;
      }
    }
  } else { /* ordinary insertion checks */
    if (NULL != next_id) {
      fprintf(stderr,
	      _("Option `%s' makes no sense without option `%s'.\n"),
	      "-N", "-P");
      errorCode = -1;
      goto quit;
    }
    if (NULL != prev_id) {
      fprintf(stderr, _("Option `%s' makes no sense without option `%s'.\n"),
	      "-u", "-P");
      errorCode = -1;
      goto quit;
    }
    if (NULL != this_id) {
      fprintf(stderr, _("Option `%s' makes no sense without option `%s'.\n"),
	      "-t", "-P");
      errorCode = -1;
      goto quit;
    }
    if (0 != interval) {
      fprintf(stderr, _("Option `%s' makes no sense without option `%s'.\n"),
	      "-i", "-P");
      errorCode = -1;
      goto quit;
    }
    if (is_sporadic) {
      fprintf(stderr, _("Option `%s' makes no sense without option `%s'.\n"),
	      "-S", "-P");
      errorCode = -1;
      goto quit;
    }
  }

  exitSignal = SEMAPHORE_CREATE(0);
  /* fundamental init */
  ctx = FSUI_start(ectx,
		   cfg,
		   "gnunet-insert",
		   NO,
		   32, /* make configurable */
		   &printstatus,
		   &verbose);

  /* first insert all of the top-level files or directories */
  tmp = string_expandFileName(ectx, filename);
  if (! do_disable_creation_time)
    ECRS_addPublicationDateToMetaData(meta);
  start_time = get_time();
  ul = FSUI_startUpload(ctx,
			tmp,
			anonymity,
			priority,			   
			! do_insert,
			YES,
			do_direct_references,			   
			meta,
			gloKeywords,
			topKeywords);
  ECRS_freeUri(gloKeywords);
  ECRS_freeUri(topKeywords);
  FREE(tmp);
  /* wait for completion */
  SEMAPHORE_DOWN(exitSignal, YES);
  es = exitSignal;
  exitSignal = NULL;
  SEMAPHORE_DESTROY(es);

  ECRS_freeMetaData(meta);
  FSUI_stop(ctx);
  
quit:
  GC_free(cfg);
  GE_free_context(ectx);
  os_done();
  return errorCode;
}

/* end of gnunet-insert.c */
