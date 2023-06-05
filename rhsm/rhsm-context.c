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

#include "rhsm-context.h"
#include "rhsm-entitlement-certificate.h"
#include "rhsm-product-certificate.h"
#include "rhsm-utils.h"
#include "rhsm-utils-private.h"
#include <string.h>

#define CONFIG_DIR            "/etc/rhsm"
#define CONFIG_DIR_HOST       "/etc/rhsm-host"
#define ENT_CERT_DIR          "/etc/pki/entitlement"
#define ENT_CERT_DIR_HOST     "/etc/pki/entitlement-host"
#define PROD_CERT_DIR         "/etc/pki/product"
#define PROD_CERT_DIR_DEFAULT "/etc/pki/product-default"

/**
 * SECTION:rhsm-context
 * @short_description: the context
 * @title: Context
 * @stability: Unstable
 * @include: rhsm.h
 */

struct _RHSMContext
{
  GObject parent_instance;

  gchar *arch;
  gchar *conf_file;

  gchar *baseurl;
  gchar *ca_cert_dir;
  gchar *repo_ca_cert;
  gchar *product_cert_dir;
  gchar *entitlement_cert_dir;
};

G_DEFINE_TYPE (RHSMContext, rhsm_context, G_TYPE_OBJECT)

enum {
  PROP_0,

  PROP_ARCH,
  PROP_CONF_FILE,

  PROP_BASEURL,
  PROP_CA_CERT_DIR,
  PROP_REPO_CA_CERT,
  PROP_PRODUCT_CERT_DIR,
  PROP_ENTITLEMENT_CERT_DIR,

  N_PROPS
};

static GParamSpec *properties [N_PROPS];

/**
 * rhsm_context_get_arch:
 * @ctx: an #RHSMContext.
 *
 * Returns: (transfer none): Architecture.
 */
const gchar *
rhsm_context_get_arch (RHSMContext *ctx)
{
  return ctx->arch;
}

/**
 * rhsm_context_set_arch:
 * @ctx: an #RHSMContext.
 * @arch: architecture.
 *
 * Returns: Nothing.
 */
void
rhsm_context_set_arch (RHSMContext *ctx,
                       const gchar *arch)
{
  g_free (ctx->arch);
  ctx->arch = g_strdup (arch);
}

/**
 * rhsm_context_get_conf_file:
 * @ctx: an #RHSMContext.
 *
 * Returns: (transfer none): Configuration file.
 */
const gchar *
rhsm_context_get_conf_file (RHSMContext *ctx)
{
  return ctx->conf_file;
}

/**
 * rhsm_context_get_baseurl:
 * @ctx: an #RHSMContext.
 *
 * Returns: (transfer none): Content base URL.
 */
const gchar *
rhsm_context_get_baseurl (RHSMContext *ctx)
{
  return ctx->baseurl;
}

/**
 * rhsm_context_set_baseurl:
 * @ctx: an #RHSMContext.
 * @baseurl: content base URL.
 *
 * Returns: Nothing.
 */
void
rhsm_context_set_baseurl (RHSMContext *ctx,
                          const gchar *baseurl)
{
  g_free (ctx->baseurl);
  ctx->baseurl = g_strdup (baseurl);
}

/**
 * rhsm_context_get_ca_cert_dir:
 * @ctx: an #RHSMContext.
 *
 * Returns: (transfer none): Server CA certificate location.
 */
const gchar *
rhsm_context_get_ca_cert_dir (RHSMContext *ctx)
{
  return ctx->ca_cert_dir;
}

/**
 * rhsm_context_set_ca_cert_dir:
 * @ctx: an #RHSMContext.
 * @ca_cert_dir: server CA certificate location.
 *
 * Returns: Nothing.
 */
void
rhsm_context_set_ca_cert_dir (RHSMContext *ctx,
                              const gchar *ca_cert_dir)
{
  g_free (ctx->ca_cert_dir);
  ctx->ca_cert_dir = g_strdup (ca_cert_dir);
}

/**
 * rhsm_context_get_repo_ca_cert:
 * @ctx: an #RHSMContext.
 *
 * Returns: (transfer none): default CA cert to use when generating yum repo configs.
 */
const gchar *
rhsm_context_get_repo_ca_cert (RHSMContext *ctx)
{
  return ctx->repo_ca_cert;
}

/**
 * rhsm_context_set_repo_ca_cert:
 * @ctx: an #RHSMContext.
 * @repo_ca_cert: default CA cert to use when generating yum repo configs.
 *
 * Returns: Nothing.
 */
void
rhsm_context_set_repo_ca_cert (RHSMContext *ctx,
                               const gchar *repo_ca_cert)
{
  g_free (ctx->repo_ca_cert);
  ctx->repo_ca_cert = g_strdup (repo_ca_cert);
}

/**
 * rhsm_context_get_product_cert_dir:
 * @ctx: an #RHSMContext.
 *
 * Returns: (transfer none): Location containing product certificates.
 */
const gchar *
rhsm_context_get_product_cert_dir (RHSMContext *ctx)
{
  return ctx->product_cert_dir;
}

/**
 * rhsm_context_set_product_cert_dir:
 * @ctx: an #RHSMContext.
 * @product_cert_dir: location containing product certificates.
 *
 * Returns: Nothing.
 */
void
rhsm_context_set_product_cert_dir (RHSMContext *ctx,
                                   const gchar *product_cert_dir)
{
  g_free (ctx->product_cert_dir);
  ctx->product_cert_dir = g_strdup (product_cert_dir);
}

/**
 * rhsm_context_get_entitlement_cert_dir:
 * @ctx: an #RHSMContext.
 *
 * Returns: (transfer none): Location containing entitlement certificate.
 */
const gchar *
rhsm_context_get_entitlement_cert_dir (RHSMContext *ctx)
{
  return ctx->entitlement_cert_dir;
}

/**
 * rhsm_context_set_entitlement_cert_dir:
 * @ctx: an #RHSMContext.
 * @entitlement_cert_dir: location containing entitlement certificate.
 *
 * Returns: Nothing.
 */
void
rhsm_context_set_entitlement_cert_dir (RHSMContext *ctx,
                                       const gchar *entitlement_cert_dir)
{
  g_free (ctx->entitlement_cert_dir);
  ctx->entitlement_cert_dir = g_strdup (entitlement_cert_dir);
}

/**
 * rhsm_context_get_product_certificates:
 * @ctx: an #RHSMContext.
 *
 * Returns: (element-type RHSM.ProductCertificate) (transfer full): list of product certificates.
 */
GPtrArray *
rhsm_context_get_product_certificates (RHSMContext *ctx)
{
  GPtrArray *certs = g_ptr_array_new_with_free_func (g_object_unref);
  g_autoptr(GHashTable) ids = g_hash_table_new (g_direct_hash, g_direct_equal);

  /* Grab working certificates from context directory */
  g_autoptr(GDir) dir = g_dir_open (ctx->product_cert_dir, 0, NULL);
  if (dir != NULL)
    {
      const gchar *fname = NULL;
      while ((fname = g_dir_read_name (dir)) != NULL)
        {
          if (!g_str_has_suffix (fname, ".pem"))
            continue;
          g_autofree gchar *file = g_build_filename (ctx->product_cert_dir, fname, NULL);
          RHSMProductCertificate *cert = rhsm_product_certificate_new_from_file (file, NULL);
          if (cert != NULL)
            {
              g_ptr_array_add (certs, cert);
              g_hash_table_add (ids, GUINT_TO_POINTER (rhsm_product_certificate_get_id (cert)));
            }
        }
    }

  /* Now fetch default certs and add missing ones */
  g_autoptr(GDir) dir_default = g_dir_open (PROD_CERT_DIR_DEFAULT, 0, NULL);
  if (dir_default != NULL)
    {
      const gchar *fname = NULL;
      while ((fname = g_dir_read_name (dir_default)) != NULL)
        {
          if (!g_str_has_suffix (fname, ".pem"))
            continue;
          g_autofree gchar *file = g_build_filename (PROD_CERT_DIR_DEFAULT, fname, NULL);
          RHSMProductCertificate *cert = rhsm_product_certificate_new_from_file (file, NULL);
          if (cert != NULL)
            {
              if (dir == NULL ||
                  !g_hash_table_contains (ids, GUINT_TO_POINTER (rhsm_product_certificate_get_id (cert))))
                g_ptr_array_add (certs, cert);
            }
        }
    }

  if (certs->len == 0)
    g_warning ("Found 0 product certificates");
  return certs;
}

/**
 * rhsm_context_get_entitlement_certificates:
 * @ctx: an #RHSMContext.
 *
 * Returns: (element-type RHSM.EntitlementCertificate) (transfer full): list of entitlement certificates.
 */
GPtrArray *
rhsm_context_get_entitlement_certificates (RHSMContext *ctx)
{
  GPtrArray *certs = g_ptr_array_new_with_free_func (g_object_unref);

  /* Grab working certificates from context directory */
  g_autoptr(GDir) dir = g_dir_open (ctx->entitlement_cert_dir, 0, NULL);
  if (dir != NULL)
    {
      const gchar *fname = NULL;
      while ((fname = g_dir_read_name (dir)) != NULL)
        {
          if (!g_str_has_suffix (fname, ".pem"))
            continue;
          g_autofree gchar *file = g_build_filename (ctx->entitlement_cert_dir, fname, NULL);
          RHSMEntitlementCertificate *cert = rhsm_entitlement_certificate_new_from_file (file, NULL);
          if (cert != NULL)
            g_ptr_array_add (certs, cert);
        }
    }

  if (certs->len == 0)
    g_warning ("Found 0 entitlement certificates");
  return certs;
}

/**
 * rhsm_context_new:
 *
 * Returns: (transfer full): a new #RHSMContext.
 */
RHSMContext *
rhsm_context_new (void)
{
  g_autoptr(GKeyFile) conf = g_key_file_new ();
  gboolean in_container = g_file_test (CONFIG_DIR_HOST, G_FILE_TEST_IS_DIR);
  gchar *conf_dir = NULL;
  if (in_container)
    conf_dir = CONFIG_DIR_HOST;
  else
    conf_dir = CONFIG_DIR;

  /* All parameters */
  g_autofree gchar *conf_file = g_build_filename (conf_dir, "rhsm.conf", NULL);
  g_autofree gchar *baseurl = NULL;
  g_autofree gchar *ca_cert_dir = NULL;
  g_autofree gchar *repo_ca_cert = NULL;
  g_autofree gchar *product_cert_dir = NULL;
  g_autofree gchar *entitlement_cert_dir = NULL;

  /* Let's parse config-file */
  if (g_key_file_load_from_file (conf, conf_file, G_KEY_FILE_NONE, NULL) &&
      g_key_file_has_group (conf, "rhsm"))
    {
      baseurl = rhsm_key_file_get_interpolated_string (conf, "rhsm", "baseurl", NULL);
      ca_cert_dir = rhsm_key_file_get_interpolated_string (conf, "rhsm", "ca_cert_dir", NULL);
      repo_ca_cert = rhsm_key_file_get_interpolated_string (conf, "rhsm", "repo_ca_cert", NULL);
      product_cert_dir = rhsm_key_file_get_interpolated_string (conf, "rhsm", "productCertDir", NULL);
      entitlement_cert_dir = rhsm_key_file_get_interpolated_string (conf, "rhsm", "entitlementCertDir", NULL);
    }

  /* Check rhsm.conf exists */
  if (!g_file_test (conf_file, G_FILE_TEST_EXISTS))
    g_debug ("Not found config file %s", conf_file);

  return g_object_new (RHSM_TYPE_CONTEXT,
                       "conf-file", conf_file,
                       "baseurl", baseurl,
                       "ca-cert-dir", ca_cert_dir,
                       "repo-ca-cert", repo_ca_cert,
                       "product-cert-dir", product_cert_dir,
                       "entitlement-cert-dir", entitlement_cert_dir,
                       NULL);
}

static void
rhsm_context_finalize (GObject *object)
{
  RHSMContext *ctx = RHSM_CONTEXT (object);

  g_clear_pointer (&ctx->arch, g_free);
  g_clear_pointer (&ctx->conf_file, g_free);

  g_clear_pointer (&ctx->baseurl, g_free);
  g_clear_pointer (&ctx->ca_cert_dir, g_free);
  g_clear_pointer (&ctx->repo_ca_cert, g_free);
  g_clear_pointer (&ctx->product_cert_dir, g_free);
  g_clear_pointer (&ctx->entitlement_cert_dir, g_free);

  G_OBJECT_CLASS (rhsm_context_parent_class)->finalize (object);
}

static void
rhsm_context_get_property (GObject    *object,
                           guint       prop_id,
                           GValue     *value,
                           GParamSpec *pspec)
{
  RHSMContext *ctx = RHSM_CONTEXT (object);

  switch (prop_id)
    {
    case PROP_ARCH:
      g_value_set_string (value, rhsm_context_get_arch (ctx));
      break;

    case PROP_CONF_FILE:
      g_value_set_string (value, rhsm_context_get_conf_file (ctx));
      break;

    case PROP_BASEURL:
      g_value_set_string (value, rhsm_context_get_baseurl (ctx));
      break;

    case PROP_CA_CERT_DIR:
      g_value_set_string (value, rhsm_context_get_ca_cert_dir (ctx));
      break;

    case PROP_REPO_CA_CERT:
      g_value_set_string (value, rhsm_context_get_repo_ca_cert (ctx));
      break;

    case PROP_PRODUCT_CERT_DIR:
      g_value_set_string (value, rhsm_context_get_product_cert_dir (ctx));
      break;

    case PROP_ENTITLEMENT_CERT_DIR:
      g_value_set_string (value, rhsm_context_get_entitlement_cert_dir (ctx));
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
rhsm_context_set_property (GObject      *object,
                           guint         prop_id,
                           const GValue *value,
                           GParamSpec   *pspec)
{
  RHSMContext *ctx = RHSM_CONTEXT (object);

  switch (prop_id)
    {
    case PROP_ARCH:
      rhsm_context_set_arch (ctx, g_value_get_string (value));
      break;

    case PROP_CONF_FILE:
      ctx->conf_file = g_value_dup_string (value);
      break;

    case PROP_BASEURL:
      rhsm_context_set_baseurl (ctx, g_value_get_string (value));
      break;

    case PROP_CA_CERT_DIR:
      rhsm_context_set_ca_cert_dir (ctx, g_value_get_string (value));
      break;

    case PROP_REPO_CA_CERT:
      rhsm_context_set_repo_ca_cert (ctx, g_value_get_string (value));
      break;

    case PROP_PRODUCT_CERT_DIR:
      rhsm_context_set_product_cert_dir (ctx, g_value_get_string (value));
      break;

    case PROP_ENTITLEMENT_CERT_DIR:
      rhsm_context_set_entitlement_cert_dir (ctx, g_value_get_string (value));
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
rhsm_context_constructed (GObject *object)
{
  RHSMContext *ctx = RHSM_CONTEXT (object);

  if (ctx->arch == NULL)
    {
      g_autoptr(GError) local_error = NULL;
      ctx->arch = rhsm_utils_get_arch (&local_error);
      if (ctx->arch == NULL)
        {
          g_warning ("Failed to automatically detect machine architecture: %s, setting to 'unknown'.",
                     local_error->message);
          ctx->arch = g_strdup ("unknown");
        }
    }

  if (ctx->baseurl == NULL)
    ctx->baseurl = g_strdup ("https://cdn.redhat.com");

  if (ctx->ca_cert_dir == NULL)
    {
      g_autofree gchar *conf_dir = g_path_get_dirname (ctx->conf_file);
      ctx->ca_cert_dir = g_build_filename (conf_dir, "ca", NULL);
    }

  if (ctx->repo_ca_cert == NULL)
    ctx->repo_ca_cert = g_build_filename (ctx->ca_cert_dir, "redhat-uep.pem", NULL);

  if (ctx->product_cert_dir == NULL)
    ctx->product_cert_dir = g_strdup (PROD_CERT_DIR);

  gboolean have_ent_host = g_file_test (ENT_CERT_DIR_HOST, G_FILE_TEST_IS_DIR);
  if (ctx->entitlement_cert_dir == NULL)
    {
      if (have_ent_host)
        ctx->entitlement_cert_dir = g_strdup (ENT_CERT_DIR_HOST);
      else
        ctx->entitlement_cert_dir = g_strdup (ENT_CERT_DIR);
    }
  else if (have_ent_host)
    {
      const gchar *entitlement_cert_dir = ctx->entitlement_cert_dir;
      g_autofree gchar *tmp = NULL;
      if (G_IS_DIR_SEPARATOR (ctx->entitlement_cert_dir [strlen (ctx->entitlement_cert_dir)]))
        {
          tmp = g_path_get_dirname (ctx->entitlement_cert_dir);
          entitlement_cert_dir = tmp;
        }
      if (g_strcmp0 (entitlement_cert_dir, ENT_CERT_DIR) == 0)
        {
          g_free (ctx->entitlement_cert_dir);
          ctx->entitlement_cert_dir = g_strdup (ENT_CERT_DIR_HOST);
        }
    }

  /* If we have conf existed and coming from /etc/rhsm-host, most probably we need to replace /etc/rhsm. */
  if (g_file_test (ctx->conf_file, G_FILE_TEST_EXISTS) && 
      g_str_has_prefix (ctx->conf_file, CONFIG_DIR_HOST))
    {
     rhsm_utils_str_replace (&ctx->ca_cert_dir, CONFIG_DIR, CONFIG_DIR_HOST);
     rhsm_utils_str_replace (&ctx->repo_ca_cert, CONFIG_DIR, CONFIG_DIR_HOST);
   }
}

static void
rhsm_context_class_init (RHSMContextClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = rhsm_context_finalize;
  object_class->get_property = rhsm_context_get_property;
  object_class->set_property = rhsm_context_set_property;
  object_class->constructed = rhsm_context_constructed;

  /**
   * RHSMContext:arch:
   */
  properties [PROP_ARCH] =
    g_param_spec_string ("arch",
                         NULL,
                         NULL,
                         NULL,
                         (G_PARAM_READWRITE |
                          G_PARAM_CONSTRUCT |
                          G_PARAM_STATIC_STRINGS));

  /**
   * RHSMContext:conf-file:
   */
  properties [PROP_CONF_FILE] =
    g_param_spec_string ("conf-file",
                         NULL,
                         NULL,
                         NULL,
                         (G_PARAM_READWRITE |
                          G_PARAM_CONSTRUCT_ONLY |
                          G_PARAM_STATIC_STRINGS));

  /**
   * RHSMContext:baseurl:
   */
  properties [PROP_BASEURL] =
    g_param_spec_string ("baseurl",
                         NULL,
                         NULL,
                         NULL,
                         (G_PARAM_READWRITE |
                          G_PARAM_CONSTRUCT |
                          G_PARAM_STATIC_STRINGS));

  /**
   * RHSMContext:ca-cert-dir:
   */
  properties [PROP_CA_CERT_DIR] =
    g_param_spec_string ("ca-cert-dir",
                         NULL,
                         NULL,
                         NULL,
                         (G_PARAM_READWRITE |
                          G_PARAM_CONSTRUCT |
                          G_PARAM_STATIC_STRINGS));

  /**
   * RHSMContext:repo-ca-cert:
   */
  properties [PROP_REPO_CA_CERT] =
    g_param_spec_string ("repo-ca-cert",
                         NULL,
                         NULL,
                         NULL,
                         (G_PARAM_READWRITE |
                          G_PARAM_CONSTRUCT |
                          G_PARAM_STATIC_STRINGS));

  /**
   * RHSMContext:product-cert-dir:
   */
  properties [PROP_PRODUCT_CERT_DIR] =
    g_param_spec_string ("product-cert-dir",
                         NULL,
                         NULL,
                         NULL,
                         (G_PARAM_READWRITE |
                          G_PARAM_CONSTRUCT |
                          G_PARAM_STATIC_STRINGS));
  /**
   * RHSMContext:entitlement-cert-dir:
   */
  properties [PROP_ENTITLEMENT_CERT_DIR] =
    g_param_spec_string ("entitlement-cert-dir",
                         NULL,
                         NULL,
                         NULL,
                         (G_PARAM_READWRITE |
                          G_PARAM_CONSTRUCT |
                          G_PARAM_STATIC_STRINGS));

  g_object_class_install_properties (object_class, N_PROPS, properties);
}

static void
rhsm_context_init (RHSMContext *ctx)
{
}
