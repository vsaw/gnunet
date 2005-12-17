/*
     This file is part of GNUnet

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
 * @file applications/afs/module/bloomfilter.h
 * @author Christian Grothoff
 * @author Igor Wronsky
 */

#ifndef FILTER_H
#define FILTER_H

int initFilters();

void doneFilters();

void deleteFilter();

void makeAvailable(const HashCode512 * key);

void makeUnavailable(const HashCode512 * key);

int testAvailable(const HashCode512 * key);

#endif
