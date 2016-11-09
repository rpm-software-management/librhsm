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

#include "rhsm-product-certificate.h"

#include <string.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define X509_EXT_REDHAT_OID "1.3.6.1.4.1.2312.9"

#define X509_EXT_REDHAT_PRODUCT_NAME_OID    X509_EXT_REDHAT_OID".1.%"G_GUINT64_FORMAT".1"
#define X509_EXT_REDHAT_PRODUCT_VERSION_OID X509_EXT_REDHAT_OID".1.%"G_GUINT64_FORMAT".2"
#define X509_EXT_REDHAT_PRODUCT_ARCH_OID    X509_EXT_REDHAT_OID".1.%"G_GUINT64_FORMAT".3"
#define X509_EXT_REDHAT_PRODUCT_TAGS_OID    X509_EXT_REDHAT_OID".1.%"G_GUINT64_FORMAT".4"

/**
 * SECTION:rhsm-product-certificate
 * @short_description: the product certificate
 * @title: Product Certificate
 * @stability: Unstable
 * @include: rhsm.h
 */

struct _RHSMProductCertificate
{
  GObject  parent_instance;

  GError  *construct_error;

  guint64 id;
  X509 *cert;
  const gchar *name;
  const gchar *version;
  const gchar *arch;
  const gchar *tags;
};

static void rhsm_product_certificate_initable_iface_init (GInitableIface *iface);

G_DEFINE_TYPE_WITH_CODE (RHSMProductCertificate, rhsm_product_certificate, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                rhsm_product_certificate_initable_iface_init))

enum {
  PROP_0,

  PROP_ID,
  PROP_CERTIFICATE,
  PROP_NAME,
  PROP_VERSION,
  PROP_ARCH,
  PROP_TAGS,

  N_PROPS
};

static GParamSpec *properties [N_PROPS];

/**
 * rhsm_product_certificate_error_quark:
 *
 * Returns: an #GQuark.
 */
G_DEFINE_QUARK (rhsm-product-certificate-error-quark, rhsm_product_certificate_error)

/*
 * x509_get_ext_data_by_oid:
 * @cert: certificate.
 * @oid: X509 extension OID.
 * @error: (nullable): an #GError.
 *
 * Returns: a new #GBytes.
 */
static GBytes *
x509_get_ext_data_by_oid (X509         *cert,
                          const gchar  *oid,
                          GError      **error)
{
  ASN1_OBJECT *obj = OBJ_txt2obj (oid, 1);
  int loc = X509_get_ext_by_OBJ (cert, obj, -1);
  ASN1_OBJECT_free (obj);
  if (loc == -1)
    {
      g_set_error (error,
                   RHSM_PRODUCT_CERTIFICATE_ERROR,
                   RHSM_PRODUCT_CERTIFICATE_ERROR_NO_EXTENSION,
                   "Extension with oid '%s' does not exist",
                   oid);
      return NULL;
    }

  X509_EXTENSION *ext = X509_get_ext (cert, loc);
  ASN1_OCTET_STRING *octet_str = X509_EXTENSION_get_data (ext);
  if (octet_str == NULL)
    return NULL;

  const unsigned char *data = octet_str->data;
  long len;
  int tag, xclass;
  int ret = ASN1_get_object (&data, &len, &tag, &xclass, octet_str->length);
  /* FIXME: is it proper way of handling error of ASN1_get_object() ? */
  if (ret & 0x80)
    {
      g_set_error_literal (error,
                           RHSM_PRODUCT_CERTIFICATE_ERROR,
                           RHSM_PRODUCT_CERTIFICATE_ERROR_FAILED,
                           ERR_error_string (ERR_get_error (), NULL));
      return NULL;
    }

  return g_bytes_new_static (data, len);
}

/**
 * rhsm_product_certificate_get_id:
 * @cert: an #RHSMProductCertificate.
 *
 * Returns: an id.
 */
guint64
rhsm_product_certificate_get_id (RHSMProductCertificate *cert)
{
  return cert->id;
}

/**
 * rhsm_product_certificate_get_name:
 * @cert: an #RHSMProductCertificate.
 *
 * Returns: (transfer none): a #gchar.
 */
const gchar *
rhsm_product_certificate_get_name (RHSMProductCertificate *cert)
{
  return cert->name;
}

/**
 * rhsm_product_certificate_get_version:
 * @cert: an #RHSMProductCertificate.
 *
 * Returns: (transfer none): a #gchar.
 */
const gchar *
rhsm_product_certificate_get_version (RHSMProductCertificate *cert)
{
  return cert->version;
}

/**
 * rhsm_product_certificate_get_arch:
 * @cert: an #RHSMProductCertificate.
 *
 * Returns: (transfer none): a #gchar.
 */
const gchar *
rhsm_product_certificate_get_arch (RHSMProductCertificate *cert)
{
  return cert->arch;
}

/**
 * rhsm_product_certificate_get_tags:
 * @cert: an #RHSMProductCertificate.
 *
 * Returns: (transfer none): a #gchar.
 */
const gchar *
rhsm_product_certificate_get_tags (RHSMProductCertificate *cert)
{
  return cert->tags;
}

/**
 * rhsm_product_certificate_new_from_file:
 * @file: path to the certificate.
 * @error: (nullable): an #GError.
 *
 * Returns: (transfer full): a new #RHSMProductCertificate.
 */
RHSMProductCertificate *
rhsm_product_certificate_new_from_file (const gchar  *file,
                                        GError      **error)
{
  g_autofree gchar *basename = g_path_get_basename (file);
  if (g_str_has_suffix (basename, ".pem"))
    basename[strlen (basename) - 4] = '\0';
  gchar *endptr = NULL;
  guint64 id = g_ascii_strtoull (basename, &endptr, 0);
  if (id == 0 && (errno != 0 || endptr != NULL))
    {
      g_set_error (error,
                   G_IO_ERROR,
                   G_IO_ERROR_INVALID_ARGUMENT,
                   "Failed to convert '%s' into guint64: Invalid data",
                   basename);
      return NULL;
    }
  else if (id == G_MAXUINT64 && errno != 0)
    {
      g_set_error (error,
                   G_IO_ERROR,
                   G_IO_ERROR_INVALID_ARGUMENT,
                   "Failed to convert '%s' into guint64: %s",
                   basename, g_strerror (errno));
      return NULL;
    }

  g_autofree gchar *certificate = NULL;
  gsize len = 0;
  if (!g_file_get_contents (file, &certificate, &len, error))
    return NULL;

  return g_initable_new (RHSM_TYPE_PRODUCT_CERTIFICATE,
                         NULL, /* cancellable */
                         error,
                         "id", id,
                         "certificate", certificate,
                         NULL);
}

/**
 * rhsm_product_certificate_discover:
 * @path: (nullable): path where to search for certificates.
 * @error: (nullable): an #GError.
 *
 * Returns: (element-type RHSM.ProductCertificate) (transfer full): list of found product certificates.
 */
GPtrArray *
rhsm_product_certificate_discover (const gchar  *path,
                                   GError      **error)
{
  g_autoptr(GError) local_error = NULL;
  g_autoptr(GPtrArray) certs = g_ptr_array_new_with_free_func (g_object_unref);

  if (path == NULL)
    path = "/etc/pki/product";

  g_autoptr(GDir) dir = g_dir_open (path, 0, error);
  if (dir == NULL)
    return NULL;

  const gchar *fname = NULL;
  while ((fname = g_dir_read_name (dir)) != NULL)
    {
      if (!g_str_has_suffix (fname, ".pem"))
        continue;
      g_autofree gchar *file = g_build_filename (path, fname, NULL);
      RHSMProductCertificate *cert = rhsm_product_certificate_new_from_file (file, NULL);
      if (cert != NULL)
        g_ptr_array_add (certs, cert);
    }

  if (certs->len == 0)
    {
      g_set_error_literal (error,
                           G_IO_ERROR,
                           G_IO_ERROR_FAILED,
                           "No certificates found");
      return NULL;
    }

  return g_ptr_array_ref (certs);
}

static void
rhsm_product_certificate_finalize (GObject *object)
{
  RHSMProductCertificate *cert = RHSM_PRODUCT_CERTIFICATE (object);

  g_clear_error (&cert->construct_error);

  g_clear_pointer (&cert->cert, X509_free);

  G_OBJECT_CLASS (rhsm_product_certificate_parent_class)->finalize (object);
}

static void
rhsm_product_certificate_get_property (GObject    *object,
                                       guint       prop_id,
                                       GValue     *value,
                                       GParamSpec *pspec)
{
  RHSMProductCertificate *cert = RHSM_PRODUCT_CERTIFICATE (object);
  BIO *bio = NULL;

  switch (prop_id)
    {
    case PROP_ID:
      g_value_set_uint64 (value, cert->id);
      break;

    case PROP_CERTIFICATE:
      bio = BIO_new (BIO_s_mem ());
      if (PEM_write_bio_X509 (bio, cert->cert) && BIO_write (bio, "\0", 1))
        {
          gchar *certificate = NULL;
          BIO_get_mem_data (bio, &certificate);
          g_value_set_string (value, certificate);
        }
      BIO_free_all (bio);
      break;

    case PROP_NAME:
      g_value_set_string (value, cert->name);
      break;

    case PROP_VERSION:
      g_value_set_string (value, cert->version);
      break;

    case PROP_ARCH:
      g_value_set_string (value, cert->arch);
      break;

    case PROP_TAGS:
      g_value_set_string (value, cert->tags);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
rhsm_product_certificate_set_property (GObject      *object,
                                       guint         prop_id,
                                       const GValue *value,
                                       GParamSpec   *pspec)
{
  RHSMProductCertificate *cert = RHSM_PRODUCT_CERTIFICATE (object);
  const gchar *cstring = NULL;
  BIO *bio = NULL;

  switch (prop_id)
    {
    case PROP_ID:
      cert->id = g_value_get_uint64 (value);
      break;

    case PROP_CERTIFICATE:
      cstring = g_value_get_string (value);
      if (cstring == NULL)
        break;
      bio = BIO_new_mem_buf ((gconstpointer)cstring, -1);
      cert->cert = PEM_read_bio_X509 (bio, NULL, NULL, NULL);
      BIO_free (bio);
      if (cert->cert == NULL && cert->construct_error == NULL)
        {
          cert->construct_error =
            g_error_new_literal (G_IO_ERROR,
                                 G_IO_ERROR_FAILED,
                                 ERR_error_string (ERR_get_error (), NULL));
        }
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static gboolean
rhsm_product_certificate_initable_init (GInitable     *initable,
                                        GCancellable  *cancellable,
                                        GError       **error)
{
  RHSMProductCertificate *cert = RHSM_PRODUCT_CERTIFICATE (initable);

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return FALSE;

  if (cert->construct_error != NULL)
    {
      g_propagate_error (error, cert->construct_error);
      cert->construct_error = NULL;
      return FALSE;
    }
  else if (cert->cert == NULL)
    {
      g_set_error_literal (error,
                           RHSM_PRODUCT_CERTIFICATE_ERROR,
                           RHSM_PRODUCT_CERTIFICATE_ERROR_FAILED,
                           "No certificate found");
      return FALSE;
    }

  gchar *oid = NULL;
  GBytes *data = NULL;

  oid = g_strdup_printf (X509_EXT_REDHAT_PRODUCT_NAME_OID, cert->id);
  if ((data = x509_get_ext_data_by_oid (cert->cert, oid, error)) == NULL)
    return FALSE;
  g_free (oid);
  cert->name = g_bytes_get_data (data, NULL);
  g_debug ("(RHSMProductCertificate *)[%p]->name: %s", cert, cert->name);
  g_bytes_unref (data);

  oid = g_strdup_printf (X509_EXT_REDHAT_PRODUCT_VERSION_OID, cert->id);
  if ((data = x509_get_ext_data_by_oid (cert->cert, oid, error)) == NULL)
    return FALSE;
  g_free (oid);
  cert->version = g_bytes_get_data (data, NULL);
  g_debug ("(RHSMProductCertificate *)[%p]->version: %s", cert, cert->version);
  g_bytes_unref (data);

  oid = g_strdup_printf (X509_EXT_REDHAT_PRODUCT_ARCH_OID, cert->id);
  if ((data = x509_get_ext_data_by_oid (cert->cert, oid, error)) == NULL)
    return FALSE;
  g_free (oid);
  cert->arch = g_bytes_get_data (data, NULL);
  g_debug ("(RHSMProductCertificate *)[%p]->arch: %s", cert, cert->arch);
  g_bytes_unref (data);

  oid = g_strdup_printf (X509_EXT_REDHAT_PRODUCT_TAGS_OID, cert->id);
  if ((data = x509_get_ext_data_by_oid (cert->cert, oid, error)) == NULL)
    return FALSE;
  g_free (oid);
  cert->tags = g_bytes_get_data (data, NULL);
  g_debug ("(RHSMProductCertificate *)[%p]->tags: %s", cert, cert->tags);
  g_bytes_unref (data);

  return TRUE;
}

static void
rhsm_product_certificate_initable_iface_init (GInitableIface *iface)
{
  iface->init = rhsm_product_certificate_initable_init;
}

static void
rhsm_product_certificate_class_init (RHSMProductCertificateClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = rhsm_product_certificate_finalize;
  object_class->get_property = rhsm_product_certificate_get_property;
  object_class->set_property = rhsm_product_certificate_set_property;

  /**
   * RHSMProductCertificate:id:
   */
  properties [PROP_ID] =
    g_param_spec_uint64 ("id",
                         NULL,
                         NULL,
                         0,
                         G_MAXUINT64,
                         0,
                         (G_PARAM_READWRITE |
                          G_PARAM_CONSTRUCT_ONLY |
                          G_PARAM_STATIC_STRINGS));

  /**
   * RHSMProductCertificate:certificate:
   */
  properties [PROP_CERTIFICATE] =
    g_param_spec_string ("certificate",
                         NULL,
                         NULL,
                         NULL,
                         (G_PARAM_READWRITE |
                          G_PARAM_CONSTRUCT_ONLY |
                          G_PARAM_STATIC_STRINGS));

  /**
   * RHSMProductCertificate:name:
   */
  properties [PROP_NAME] =
    g_param_spec_string ("name",
                         NULL,
                         NULL,
                         NULL,
                         (G_PARAM_READABLE |
                          G_PARAM_STATIC_STRINGS));

  /**
   * RHSMProductCertificate:version:
   */
  properties [PROP_VERSION] =
    g_param_spec_string ("version",
                         NULL,
                         NULL,
                         NULL,
                         (G_PARAM_READABLE |
                          G_PARAM_STATIC_STRINGS));

  /**
   * RHSMProductCertificate:arch:
   */
  properties [PROP_ARCH] =
    g_param_spec_string ("arch",
                         NULL,
                         NULL,
                         NULL,
                         (G_PARAM_READABLE |
                          G_PARAM_STATIC_STRINGS));

  /**
   * RHSMProductCertificate:tags:
   */
  properties [PROP_TAGS] =
    g_param_spec_string ("tags",
                         NULL,
                         NULL,
                         NULL,
                         (G_PARAM_READABLE |
                          G_PARAM_STATIC_STRINGS));

  g_object_class_install_properties (object_class, N_PROPS, properties);
}

static void
rhsm_product_certificate_init (RHSMProductCertificate *cert)
{
}
