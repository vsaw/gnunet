/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @file applications/datastore/filter.c
 * @brief filter for requests to avoid sqstore lookups
 * @author Christian Grothoff
 */

#include "gnunet_directories.h"
#include "gnunet_util.h"
#include "gnunet_util_containers.h"
#include "filter.h"
#include "platform.h"

/**
 * Filter.
 */
static struct Bloomfilter * filter;

static char * getFilterName(struct GE_Context * ectx,
  		    struct GC_Configuration * cfg) {
  char * fn;
  char * bf;

  fn = NULL;
  if (-1 == GC_get_configuration_value_filename(cfg,
  				      "FS",
  				      "DIR",
  				      VAR_DAEMON_DIRECTORY "/fs",
  				      &fn))
    return NULL;
  if (OK != disk_directory_create(ectx,
  			  fn)) {
    FREE(fn);
    return NULL;
  }
  bf = MALLOC(strlen(fn)+
        strlen("/bloomfilter")+1);
  strcpy(bf, fn);
  strcat(bf, "/bloomfilter");
  FREE(fn);
  return bf;
}

int initFilters(struct GE_Context * ectx,
  	struct GC_Configuration * cfg) {
  char * bf;
  unsigned long long quota; /* in kb */
  unsigned int bf_size;

  if (-1 == GC_get_configuration_value_number(cfg,
  				      "FS",
  				      "QUOTA",
  				      0,
  				      ((unsigned long long)-1)/1024/1024,
  				      1024,
  				      &quota))
    return SYSERR;
  quota *= 1024;
  bf_size = quota / 32; /* 8 bit per entry, 1 bit per 32 kb in DB */
  bf = getFilterName(ectx, cfg);
  if (bf == NULL)
    return SYSERR;
  filter
    = loadBloomfilter(ectx,
  	      bf,
  	      bf_size,
  	      5); /* approx. 3% false positives at max use */
  FREE(bf);
  if (filter == NULL)
    return SYSERR;
  return OK;
}

void doneFilters() {
  if (filter != NULL)
    freeBloomfilter(filter);
}

void deleteFilter(struct GE_Context * ectx,
  	  struct GC_Configuration * cfg) {
  char * fn;

  GE_ASSERT(ectx, filter == NULL);
  fn = getFilterName(ectx, cfg);
  UNLINK(fn);
  FREE(fn);
}

void makeAvailable(const HashCode512 * key) {
  addToBloomfilter(filter, key);
}

void makeUnavailable(const HashCode512 * key) {
  delFromBloomfilter(filter, key);
}

int testAvailable(const HashCode512 * key) {
  return testBloomfilter(filter,
  		 key);
}

/* end of filter.c */

