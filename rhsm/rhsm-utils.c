/*
 * Copyright (C) 2016  Igor Gnatenko <ignatenko@redhat.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "rhsm-utils.h"
#include "rhsm-utils-private.h"
#include "rhsm-entitlement-certificate.h"
#include "rhsm-product-certificate.h"
#include <errno.h>
#include <string.h>
#include <sys/utsname.h>
#include <glib.h>
#include <gio/gio.h>
#include <json-glib/json-glib.h>

/*
 * rhsm_utils_str_replace:
 * @haystack: (inout): pointer to a nul-terminated string.
 * @needle: the nul-terminated string to search for.
 * @replacement: the nul-terminated string to replace @needle with.
 *
 * Note that function replaces only first occurence of @needle.
 *
 * Returns: (transfer none): nul-terminated string.
 */
gchar *
rhsm_utils_str_replace (gchar       **haystack,
                        const gchar  *needle,
                        const gchar  *replacement)
{
  const gchar *pos = strstr (*haystack, needle);

  if (pos != NULL)
    {
      GString *tmp = g_string_sized_new (strlen (*haystack) - strlen (needle) + strlen (replacement));
      g_string_append_len (tmp, *haystack, pos - *haystack);
      g_string_append (tmp, replacement);
      g_string_append (tmp, pos + strlen (needle));

      g_free (*haystack);
      *haystack = g_string_free (tmp, FALSE);
    }

  return *haystack;
}

/**
 * rhsm_utils_get_arch:
 * @error: (nullable): an #GError.
 *
 * Returns: (transfer full): Machine architecture.
 */
gchar *
rhsm_utils_get_arch (GError **error)
{
  struct utsname un;

  if (uname (&un) != 0)
    {
      g_set_error_literal (error,
                           G_IO_ERROR,
                           G_IO_ERROR_FAILED,
                           g_strerror (errno));
      return NULL;
    }

  return g_strdup (un.machine);
}

/*
 * rhsm_key_file_get_interpolated_string:
 * @key_file: an #GKeyFile.
 * @group_name: a group name.
 * @key: a key.
 * @error: (nullable): an #GError.
 *
 * Similar to g_key_file_get_string(), but with interpolation.
 * For example, having keyfile:
 * |[
 * [rhsm]
 * ca_cert_dir=/etc/rhsm/ca/
 * repo_ca_cert=%(ca_cert_dir)sredhat-uep.pem
 * ]|
 * |[<!-- language="C" -->
 * key_file_get_interpolated_string (key_file, "rhsm", "repo_ca_cert", NULL);
 * ]|
 * will return "/etc/rhsm/ca/redhat-uep.pem
 *
 * If "sub-key" can't be found, interpolation stays unmodified.
 *
 * Function does not do deep interpolation, only 1 level.
 *
 * Returns: (transfer full): a newly allocated string or %NULL.
 */
gchar *
rhsm_key_file_get_interpolated_string (GKeyFile     *key_file,
                                       const gchar  *group_name,
                                       const gchar  *key,
                                       GError      **error)
{
  g_autoptr(GRegex) re = g_regex_new ("%\\((.+)\\)s", G_REGEX_UNGREEDY, 0, NULL);
  g_assert_nonnull (re); /* this should never happen as regex is correct */
  g_autoptr(GMatchInfo) mi = NULL;

  gchar *str = g_key_file_get_string (key_file, group_name, key, error);
  if (str == NULL)
    return NULL;

  g_regex_match (re, str, 0, &mi);
  while (g_match_info_matches (mi))
    {
      g_autofree gchar *substr = g_match_info_fetch (mi, 0);
      g_autofree gchar *subkey = g_match_info_fetch (mi, 1);
      g_autofree gchar *value = g_key_file_get_string (key_file, group_name, subkey, NULL);
      if (value != NULL)
        rhsm_utils_str_replace (&str, substr, value);

      g_match_info_next (mi, NULL);
    }

  return str;
}

/*
 * rhsm_json_array_contains:
 * @array: an #JsonArray.
 * @needle: a nul-terminated string to search.
 *
 * Returns: %TRUE if @needle found in @array, otherwise %FALSE.
 */
static gboolean
rhsm_json_array_contains_string (JsonArray   *array,
                                 const gchar *needle)
{
  g_autoptr(GList) list = json_array_get_elements (array);
  if (list == NULL)
    return TRUE;
  for (const GList *lst = list; lst != NULL; lst = lst->next)
    {
      const gchar *tmp = json_node_get_string (lst->data);
      if (g_strcmp0 (tmp, needle) == 0)
        return TRUE;
    }

  return FALSE;
}

/*
 * rhsm_json_array_is_subset_of_hash_table:
 * @array: an #JsonArray.
 * @hash_table: an #GHashTable.
 *
 * Returns: %TRUE if @array is subset of keys from @hash_table, otherwise %FALSE.
 */
static gboolean
rhsm_json_array_is_subset_of_hash_table (JsonArray  *array,
                                         GHashTable *hash_table)
{
  g_autoptr(GList) list = json_array_get_elements (array);
  for (const GList *lst = list; lst != NULL; lst = lst->next)
    {
      const gchar *tmp = json_node_get_string (lst->data);
      if (!g_hash_table_contains (hash_table, tmp))
        return FALSE;
    }

  return TRUE;
}

/**
 * rhsm_utils_yum_repo_from_context:
 * @ctx: an #RHSMContext.
 *
 * Returns: (transfer full): a new #GKeyFile.
 */
GKeyFile *
rhsm_utils_yum_repo_from_context (RHSMContext *ctx)
{
  GKeyFile *repofile = g_key_file_new ();

  g_autoptr(GPtrArray) entitlements = rhsm_context_get_entitlement_certificates (ctx);
  g_autoptr(GPtrArray) products = rhsm_context_get_product_certificates (ctx);

  /* Get all available tags from each of the products */
  g_autoptr(GHashTable) available_tags = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
  for (guint i = 0; i < products->len; i++)
    {
      RHSMProductCertificate *product = g_ptr_array_index (products, i);
      g_auto(GStrv) tags = g_strsplit (rhsm_product_certificate_get_tags (product), ",", -1);
      for (GStrv tag = tags; *tag != NULL; tag++)
        g_hash_table_add (available_tags, g_strdup (*tag));
    }

  for (guint i = 0; i < entitlements->len; i++)
    {
      RHSMEntitlementCertificate *entitlement = g_ptr_array_index (entitlements, i);
      JsonNode *ent = rhsm_entitlement_certificate_get_entitlement (entitlement);
      g_autoptr(JsonNode) contents = json_path_query ("$.products[*].content[*]", ent, NULL);
      /* Even there is non-matching JsonPath, node will be empty array */
      g_assert_nonnull (contents);

      g_autoptr(GList) elements = json_array_get_elements (json_node_get_array (contents));
      const gchar *ctx_arch = rhsm_context_get_arch (ctx);
      const gchar *ctx_baseurl = rhsm_context_get_baseurl (ctx);
      const gchar *ctx_ca_cert = rhsm_context_get_repo_ca_cert (ctx);
      for (const GList *element = elements; element != NULL; element = element->next)
        {
          JsonObject *repo = json_node_get_object (element->data);

          /* Filter by type=yum */
          const gchar *type = json_object_get_string_member (repo, "type");
          if (type == NULL || g_strcmp0 (type, "yum") != 0)
            continue;

          /* Filter by arches vs context one */
          if (json_object_has_member (repo, "arches"))
            {
              JsonArray *arr = json_object_get_array_member (repo, "arches");
              if (!rhsm_json_array_contains_string (arr, ctx_arch))
                continue;
            }

          /* Filter by required tags vs available tags */
          if (json_object_has_member (repo, "required_tags"))
            {
              JsonArray *arr = json_object_get_array_member (repo, "required_tags");
              if (!rhsm_json_array_is_subset_of_hash_table (arr, available_tags))
                continue;
            }

          /* Now we have only available repos */
          const gchar *id = json_object_get_string_member (repo, "label");
          const gchar *name = json_object_get_string_member (repo, "name");
          const gchar *path = json_object_get_string_member (repo, "path");

          /*
           * The "enabled" option defaults to "true".
           * If a content (repository) is enabled, the option is missing in the data,
           * most likely to save limited space in the certificate.
           */
          gboolean enabled = TRUE;
          if (json_object_has_member (repo, "enabled"))
            enabled = json_object_get_boolean_member (repo, "enabled");

          if (id == NULL || name == NULL || path == NULL)
            continue; /* TODO: make some error reporting here */

          /* Clashing repositories */
          if (g_key_file_has_group (repofile, id))
            {
              g_debug ("Repository '%s' has been already added, skipping", id);
              continue;
            }

          g_autofree gchar *baseurl = g_strconcat (ctx_baseurl, path, NULL);
          g_key_file_set_string (repofile, id, "name", name);
          g_key_file_set_string (repofile, id, "baseurl", baseurl);
          g_key_file_set_boolean (repofile, id, "enabled", enabled);

          if (json_object_has_member (repo, "gpg_url"))
            {
              const gchar *gpg_url = json_object_get_string_member (repo, "gpg_url");
              g_key_file_set_string (repofile, id, "gpgkey", gpg_url);
              g_key_file_set_boolean (repofile, id, "gpgcheck", TRUE);
            }
          else
            {
              /* FIXME: Do we want to enforce gpgcheck? It's unsecure repo. */
              g_key_file_set_boolean (repofile, id, "gpgcheck", FALSE);
            }

          gint64 md_expire = json_object_get_int_member (repo, "metadata_expire");
          g_key_file_set_int64 (repofile, id, "metadata_expire", md_expire);

          const gchar *cert = rhsm_entitlement_certificate_get_file (entitlement);
          g_key_file_set_string (repofile, id, "sslclientcert", cert);
          const gchar *key = rhsm_entitlement_certificate_get_keyfile (entitlement);
          g_key_file_set_string (repofile, id, "sslclientkey", key);
          g_key_file_set_string (repofile, id, "sslcacert", ctx_ca_cert);
          g_key_file_set_boolean (repofile, id, "sslverify", TRUE);

          /* TODO: set proxy info */
        }
    }

  return repofile;
}
