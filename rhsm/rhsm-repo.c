/*
 * Copyright (C) 2016  Michael Mraka <michael.mraka@redhat.com>
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

#include <sys/utsname.h>
#include <errno.h>

#include "rhsm-repo.h"

#if !JSON_CHECK_VERSION (1, 1, 2)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (JsonNode, json_node_free)
#endif

/*
 * get_arch:
 * @error: (nullable): an #GError.
 *
 * Returns: (transfer full): machine architecture.
 */
gchar *
get_arch (GError **error)
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
 * match_arch:
 * @arches: (element-type Json.Node): arches.
 * @arch: current architecture
 *
 * Returns: %TRUE if current architecture in the list, %FALSE otherwise.
 */
static gboolean
rhsm_repo_json_match_arch (JsonObject  *repo,
                           const gchar *arch)
{
  if (!json_object_has_member (repo, "arches"))
    return TRUE;

  JsonArray *arches_array = json_object_get_array_member (repo, "arches");
  g_autoptr(GList) arches = json_array_get_elements (arches_array);
  for (const GList *lst = arches; lst != NULL; lst = lst->next)
    {
      const gchar *tmp_arch = json_node_get_string ((JsonNode *)lst->data);
      if (g_strcmp0 (arch, tmp_arch) != 0)
        return FALSE;
    }

  return TRUE;
}

/*
 * match_tags:
 * @required_tags: (element-type Json.Node): required tags.
 * @available_tags: (element-type utf8): available tags.
 *
 * Returns: %TRUE if all required tags are satisfied, %FALSE otherwise.
 */
static gboolean
rhsm_repo_json_match_tags (JsonObject *repo,
                           GHashTable *available_tags)
{
  if (!json_object_has_member (repo, "required_tags"))
    return TRUE;

  JsonArray *required_tags_array = json_object_get_array_member (repo, "required_tags");
  g_autoptr(GList) required_tags = json_array_get_elements (required_tags_array);
  for (const GList *lst = required_tags; lst != NULL; lst = lst->next)
    {
      const gchar *req_tag = json_node_get_string ((JsonNode *)lst->data);
      if (!g_hash_table_contains (available_tags, req_tag))
        return FALSE;
    }

  return TRUE;
}

/**
 * repo_from_certificates:
 * @entitlement: an #RHSMEntitlementCertificate.
 * @products: (element-type RHSM.ProductCertificate): list of #RHSMProductCertificate.
 * @error: (nullable): an #GError.
 *
 * Returns: (transfer full): a new #GKeyFile.
 */
GKeyFile *
rhsm_repo_from_certificates (RHSMEntitlementCertificate  *entitlement,
                             GPtrArray                   *products,
                             GError                     **error)
{
  g_autoptr(GKeyFile) repofile = g_key_file_new ();

  JsonNode *ent = rhsm_entitlement_certificate_get_entitlement (entitlement);
  g_autoptr(JsonNode) contents = json_path_query ("$.products[*].content[*]", ent, error);
  if (contents == NULL)
    return NULL;

  /* Available tags are all tags from all possible products */
  g_autoptr(GHashTable) available_tags = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
  for (guint i = 0; i < products->len; i++)
    {
      RHSMProductCertificate *product = RHSM_PRODUCT_CERTIFICATE (g_ptr_array_index (products, i));
      g_auto(GStrv) prod_tags = g_strsplit (rhsm_product_certificate_get_tags (product), ",", -1);
      for (GStrv tag = prod_tags; *tag != NULL; tag++)
        g_hash_table_add (available_tags, g_strdup (*tag));
    }

  /* Current architecture */
  g_autofree gchar *arch = get_arch (error);
  if (arch == NULL)
    return NULL;

  g_autoptr(GList) elements = json_array_get_elements (json_node_get_array (contents));
  for (const GList *element = elements; element != NULL; element = element->next)
    {
      JsonObject *repo = json_node_get_object ((JsonNode *)element->data);

      /* Filter by type=yum */
      const gchar *type = json_object_get_string_member (repo, "type");
      if (type == NULL || g_strcmp0 (type, "yum") != 0)
        continue;

      /* Filter by required_tags vs available tags */
      if (!rhsm_repo_json_match_tags (repo, available_tags))
        continue;

      /* Filter by arches vs runtime one */
      if (!rhsm_repo_json_match_arch (repo, arch))
        continue;

      /* Now we have only available repos */
      const gchar *id = json_object_get_string_member (repo, "label");
      const gchar *name = json_object_get_string_member (repo, "name");
      const gchar *path = json_object_get_string_member (repo, "path");
      gboolean enabled = FALSE;
      if (json_object_has_member (repo, "enabled"))
        enabled = json_object_get_boolean_member (repo, "enabled");
      if (id == NULL || name == NULL || path == NULL)
        continue; /* TODO: make some error reporting here */
      g_autofree gchar *baseurl = g_strconcat ("https://cdn.redhat.com", path, NULL);
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
          /* FIXME: Should we want here also? It's unsecure repo */
          g_key_file_set_boolean (repofile, id, "gpgcheck", FALSE);
        }

      gint64 md_expire = json_object_get_int_member (repo, "metadata_expire");
      g_key_file_set_int64 (repofile, id, "metadata_expire", md_expire);

      const gchar *cert = rhsm_entitlement_certificate_get_file (entitlement);
      g_key_file_set_string (repofile, id, "sslclientkey", cert);
      const gchar *key = rhsm_entitlement_certificate_get_keyfile (entitlement);
      g_key_file_set_string (repofile, id, "sslclientcert", key);
      g_key_file_set_string (repofile, id, "sslcacert", "/etc/rhsm/ca/redhat-uep.pem");
      g_key_file_set_boolean (repofile, id, "sslverify", TRUE);

      /* TODO: set proxy info */
    }

  return g_key_file_ref (repofile);
}
