/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/initialize.c
 * @brief functions to initializing libgnunetutil in the proper order.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"

/**
 * Initialize the util library.
 */
int __attribute__ ((constructor))  gnunet_util_init() {
#ifdef MINGW
  if (InitWinEnv() != ERROR_SUCCESS)
  	return SYSERR;
#endif
#if ENABLE_NLS
  setlocale (LC_ALL, "");
  BINDTEXTDOMAIN("GNUnet", LOCALEDIR);
  textdomain("GNUnet");
#endif
  return OK;
}

void __attribute__ ((destructor)) gnunet_util_fini() {
#ifdef MINGW
  ShutdownWinEnv();
#endif
}

/* end of initialize.c */
