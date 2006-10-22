/*
     This file is part of GNUnet.
     (C) 2006 Christian Grothoff (and other contributing authors)

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
 * @file src/setup/tree.c
 * @brief tree API (guile integration)
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "gnunet_setup_lib.h"
#include "tree.h"
#include "platform.h"

#include <libguile.h>

typedef struct {
  VisibilityChangeListener vcl;
  void * ctx;
  struct GNS_Tree * root;
  struct GC_Configuration * cfg;
} TC;

/* ********************** scheme smob boxing ***************** */

static scm_t_bits tc_tag;

static scm_t_bits tree_tag;

static SCM
box_tc(TC * tc) {
  SCM smob;

  SCM_NEWSMOB (smob, tc_tag, tc);
  return smob;
}

static SCM
box_tree(struct GNS_Tree * tree) {
  SCM smob;

  SCM_NEWSMOB (smob, tree_tag, tree);
  return smob;
}

static size_t
free_box(SCM smob) {
  return 0;
}

static int
print_tc(SCM tc_smob,
	 SCM port,
	 scm_print_state *pstate) {
  /* TC * tc = (TC *) SCM_SMOB_DATA (tc_smob); */
  scm_puts ("TC", port);
  /* non-zero means success */
  return 1;
}

static int
print_tree(SCM tree_smob,
	   SCM port,
	   scm_print_state *pstate) {
  /* struct GNS_Tree * tree = (struct GNS_Tree *) SCM_SMOB_DATA (tree_smob); */

  scm_puts ("Tree", port);
  /* non-zero means success */
  return 1;
}

/* **************************** tree API ****************** */

struct GNS_Tree *
tree_lookup(struct GNS_Tree * root,
	    const char * section,
	    const char * option) {
  int i;
  struct GNS_Tree * ret;

  if ( (root->section != NULL) &&
       (root->option != NULL) &&
       (0 == strcmp(section, root->section)) &&
       (0 == strcmp(option, root->option)) )
    return root;
  i = 0;
  while (root->children[i] != NULL) {
    ret = tree_lookup(root->children[i],
		      section,
		      option);
    if (ret != NULL)
      return ret;
    i++;
  }
  return NULL;
}

SCM get_option(SCM smob,
	       SCM section,
	       SCM option) {
  TC * tc;
  char * opt;
  char * sec;
  struct GNS_Tree * t;

  SCM_ASSERT(SCM_SMOB_PREDICATE(tc_tag, smob), smob, SCM_ARG1, "get_option");
  SCM_ASSERT(scm_string_p(option), option, SCM_ARG2, "get_option");
  SCM_ASSERT(scm_string_p(section), section, SCM_ARG3, "get_option");
  tc    = (TC *) SCM_SMOB_DATA(smob);
  opt = scm_to_locale_string(option);
  sec = scm_to_locale_string(section);
  t = tree_lookup(tc->root,
		  sec,
		  opt);
  if (t == NULL)
    return SCM_EOL;
  switch (t->type & GNS_TypeMask) {
  case 0:
    return SCM_EOL; /* no value */
  case GNS_Boolean:
    return (t->value.Boolean.val) ? SCM_BOOL_T : SCM_BOOL_F;
  case GNS_UInt64:
    return scm_from_uint64(t->value.UInt64.val);
  case GNS_Double:
    return scm_from_double(t->value.Double.val);
  case GNS_String:
    return scm_from_locale_string(t->value.String.val);
  }
  GE_BREAK(NULL, 0);
  return SCM_EOL;
}
	
/**
 * Change the visibility of an entry in the
 * tree (and notify listeners about change).
 */
SCM change_visible(SCM smob,
		   SCM section,
		   SCM option,
		   SCM yesno) {
  TC * tc;
  char * opt;
  char * sec;
  int val;
  struct GNS_Tree * t;

  SCM_ASSERT(SCM_SMOB_PREDICATE(tc_tag, smob), smob, SCM_ARG1, "change_visible");
  SCM_ASSERT(scm_string_p(option), option, SCM_ARG2, "change_visible");
  SCM_ASSERT(scm_string_p(section), section, SCM_ARG3, "change_visible");
  SCM_ASSERT(scm_boolean_p(yesno), yesno, SCM_ARG4, "change_visible");

  tc    = (TC *) SCM_SMOB_DATA(smob);
  opt = scm_to_locale_string(option);
  sec = scm_to_locale_string(section);
  val = scm_is_true(yesno) ? 1 : 0;
  t = tree_lookup(tc->root,
		  sec,
		  opt);
  if (t != NULL) {
    t->visible = val;
    tc->vcl(tc->ctx,
	    t);
  } else {
    fprintf(stderr,
	    _("Internal error: entry `%s' in section `%s' not found for visibility change!\n"),
	    opt,
	    sec);
  }
  if (sec != NULL)
    free(sec);
  if (opt != NULL)
    free(opt);
  return SCM_EOL;
}

/**
 * Set an option.
 */
SCM set_option(SCM smob,
	       SCM section,
	       SCM option,
	       SCM value) {
  TC * tc;
  char * opt;
  char * sec;
  char * val;

  SCM_ASSERT(SCM_SMOB_PREDICATE(tc_tag, smob), smob, SCM_ARG1, "set_option");
  SCM_ASSERT(scm_string_p(option), option, SCM_ARG2, "set_option");
  SCM_ASSERT(scm_string_p(section), section, SCM_ARG3, "set_option");
  SCM_ASSERT(scm_string_p(value), value, SCM_ARG4, "set_option");
  tc    = (TC *) SCM_SMOB_DATA(smob);
  opt = scm_to_locale_string(option);
  sec = scm_to_locale_string(section);
  val = scm_to_locale_string(value);
  GC_set_configuration_value_string(tc->cfg,
				    NULL,
				    sec,
				    opt,
				    val);
  if (sec != NULL)
    free(sec);
  if (val != NULL)
    free(val);
  if (opt != NULL)
    free(opt);
  return SCM_EOL;
}

/**
 * Create a node in the tree.
 *
 * @param value the current value (must also be default value)
 * @param range information about the legal range of values;
 *        maybe list of strings for string values or pair
 *        min/max for integers
 */
SCM build_tree_node(SCM section,
		    SCM option,
		    SCM description,
		    SCM help,
		    SCM children,
		    SCM visible,
		    SCM value,
		    SCM range) {
  struct GNS_Tree * tree;
  SCM child;
  int i;
  int clen;
  int len;

  /* verify arguments */
  SCM_ASSERT(scm_string_p(section), section, SCM_ARG1, "build_tree_node");
  SCM_ASSERT(scm_string_p(option), option, SCM_ARG2, "build_tree_node");
  SCM_ASSERT(scm_string_p(description), description, SCM_ARG3, "build_tree_node");
  SCM_ASSERT(scm_string_p(help), help, SCM_ARG4, "build_tree_node");
  SCM_ASSERT(scm_list_p(children), children, SCM_ARG5, "build_tree_node");
  clen = scm_to_int(scm_length(children));
  for (i=0;i<clen;i++) {
    child = scm_list_ref(children, scm_from_signed_integer(i));
    SCM_ASSERT(SCM_SMOB_PREDICATE(tree_tag, child),
	       children, SCM_ARG5, "build_tree_node");
  }
  SCM_ASSERT(scm_boolean_p(visible), visible, SCM_ARG6, "build_tree_node");
  if (scm_is_string(value)) {
    SCM_ASSERT(scm_list_p(range), range, SCM_ARGn, "build_tree_node");
    len = scm_to_int(scm_length(range));
    for (i=0;i<len;i++)
      SCM_ASSERT(scm_string_p(scm_list_ref(range, scm_from_signed_integer(i))),
		 range, SCM_ARGn, "build_tree_node");
  } else if (scm_is_integer(value)) {
    SCM_ASSERT(scm_pair_p(range),
	       range, SCM_ARGn, "build_tree_node");
    SCM_ASSERT(scm_is_integer(SCM_CAR(range)),
	       range, SCM_ARGn, "build_tree_node");
    SCM_ASSERT(scm_is_integer(SCM_CDR(range)),
	       range, SCM_ARGn, "build_tree_node");
  } else if (scm_is_true(scm_real_p(value))) {
    /* no checks */
  } else if (scm_is_true(scm_boolean_p(value))) {
    /* no checks */
  } else {
    SCM_ASSERT(0,
	       range,
	       SCM_ARG7,
	       "build_tree_node"); /* invalid type */
  }

  /* construct C object */
  tree = MALLOC(sizeof(struct GNS_Tree));
  tree->section = scm_to_locale_string(section);
  tree->option = scm_to_locale_string(option);
  tree->description = scm_to_locale_string(description);
  tree->help = scm_to_locale_string(help);
  tree->children = MALLOC(sizeof(struct GNS_Tree*) * (clen + 1));
  for (i=0;i<clen;i++) {
    child = scm_list_ref(children, scm_from_signed_integer(i));
    tree->children[i] = (struct GNS_Tree*) SCM_SMOB_DATA(child);
  }
  tree->children[clen] = NULL;
  tree->type = (clen == 0) ? GNS_Leaf : GNS_Node;
  tree->visible = scm_is_true(visible);

  if (scm_is_string(value)) {
    tree->value.String.val = scm_to_locale_string(value);
    tree->value.String.def = scm_to_locale_string(value);
    len = scm_to_int(scm_length(range));
    tree->value.String.legalRange = MALLOC(sizeof(char*) * (len + 1));
    for (i=0;i<len;i++)
      tree->value.String.legalRange[i]
	= scm_to_locale_string(scm_list_ref(range,
					    scm_from_signed_integer(i)));
    tree->value.String.legalRange[len] = NULL;
    tree->type |= GNS_String;
  } else if (scm_is_integer(value)) {
    tree->value.UInt64.val = scm_to_uint64(value);
    tree->value.UInt64.def = scm_to_uint64(value);
    tree->value.UInt64.min = scm_to_uint64(SCM_CAR(range));
    tree->value.UInt64.max = scm_to_uint64(SCM_CDR(range));
    tree->type |= GNS_UInt64;
  } else if (scm_is_true(scm_real_p(value))) {
    tree->value.Double.val = scm_to_double(value);
    tree->value.Double.def = scm_to_double(value);
    tree->type |= GNS_Double;
  } else if (scm_is_true(scm_boolean_p(value))) {
    tree->value.Boolean.val = scm_is_true(value);
    tree->value.Boolean.def = scm_is_true(value);
    tree->type |= GNS_Boolean;
  }
  /* box and return */
  return box_tree(tree);
}

/**
 * Parse the specification file and create the tree.
 * Set all values to defaults.
 */
static void *
parse_internal(void * spec) {
  const char * specification = spec;
  SCM proc;
  SCM smob;

  scm_c_primitive_load(specification);
  proc = scm_variable_ref(scm_c_lookup("gnunet-config-setup"));
  smob = scm_apply_0(proc, SCM_EOL);
  return (void*) SCM_SMOB_DATA(smob);
}


struct GNS_Tree *
tree_parse(struct GE_Context * ectx,
	   const char * specification) {
  struct GNS_Tree * ret;

  ret = scm_with_guile(parse_internal,
		       (void*) specification);
  if (ret != NULL)
    ret->type = GNS_Root;
  return ret;
}

static void *
notify_change_internal(void * cls) {
  TC * tc = cls;
  SCM smob_ctx;
  SCM proc;

  proc = scm_variable_ref(scm_c_lookup("gnunet-config-change"));
  smob_ctx = box_tc(tc);
  scm_apply_1(proc, smob_ctx, SCM_EOL);
  return NULL;
}

/**
 * A value in the tree has been changed.  Must only
 * be called after "tree_parse" has already been
 * executed.
 *
 * Update visibility (and notify about changes).
 */
void tree_notify_change(struct GC_Configuration * cfg,
			VisibilityChangeListener vcl,
			void * ctx,
			struct GE_Context * ectx,
			struct GNS_Tree * root,
			struct GNS_Tree * change) {
  TC tc;

  tc.cfg = cfg;
  tc.vcl = vcl;
  tc.ctx = ctx;
  tc.root = root;
  scm_with_guile(&notify_change_internal, &tc);
}

static void * init_helper(void * unused) {
  tc_tag = scm_make_smob_type ("tc", 0);
  scm_set_smob_mark (tc_tag, NULL);
  scm_set_smob_free (tc_tag, free_box);
  scm_set_smob_print (tc_tag, print_tc);

  tree_tag = scm_make_smob_type ("tc", sizeof (struct GNS_Tree));
  scm_set_smob_mark (tree_tag, NULL);
  scm_set_smob_free (tree_tag, free_box);
  scm_set_smob_print (tree_tag, print_tree);
  scm_c_define_gsubr("change-visible",
		     4, 0, 0,
		     &change_visible);
  scm_c_define_gsubr("build-tree-node",
		     8, 0, 0,
		     &build_tree_node);
  scm_c_define_gsubr("get-option",
		     3, 0, 0,
		     &get_option);
  scm_c_define_gsubr("set-option",
		     4, 0, 0,
		     &set_option);
  return NULL;
}

/**
 * Hopefully this initialization can be done
 * once and for all outside of a guile context.
 * If not, we'll have to move it into the
 * _internal methods.
 */
void __attribute__ ((constructor)) gns_scheme_init() {
#ifdef MINGW
  char *oldpath, *env;
  char load[MAX_PATH + 1];
  int len;

  InitWinEnv();

  /* add path of "system" .scm files to guile's load path */
  plibc_conv_to_win_path("/share/guile/1.8/", load);
  len = 0;
  oldpath = getenv("GUILE_LOAD_PATH");
  if (oldpath)
    len = strlen(oldpath);
  env = malloc(len + strlen(load) + 18);
  strcpy(env, "GUILE_LOAD_PATH=");
  if (oldpath) {
    strcat(env, oldpath);
    strcat(env, ";");
  }
  strcat(env, load);
  putenv(env);
  free(env);
#endif

  /* Guile doesn't get the stack boundaries right in our case.
     This workaround ensures that Guile's garbage collector will never run. */
  putenv("GUILE_INIT_MALLOC_LIMIT=100000000");

  scm_with_guile(&init_helper, NULL);
}

void __attribute__ ((destructor)) gns_scheme_fin() {
#ifdef MINGW
  ShutdownWinEnv();
#endif
}

/* end of tree.c */
