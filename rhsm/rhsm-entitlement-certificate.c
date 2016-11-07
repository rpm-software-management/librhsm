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

#include "rhsm-entitlement-certificate.h"

#include <string.h>

#if !JSON_CHECK_VERSION (1, 1, 2)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (JsonParser, g_object_unref)
#endif

/**
 * SECTION:rhsm-entitlement-certificate
 * @short_description: the entitlement certificate
 * @title: Entitlement Certificate
 * @stability: Unstable
 * @include: rhsm.h
 */

struct _RHSMEntitlementCertificate
{
  GObject parent_instance;

  GError *construct_error;

  JsonParser *entitlement_parser;
  gchar *file;
  gchar *keyfile;
};

static void rhsm_entitlement_certificate_initable_iface_init (GInitableIface *iface);

G_DEFINE_TYPE_WITH_CODE (RHSMEntitlementCertificate, rhsm_entitlement_certificate, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                rhsm_entitlement_certificate_initable_iface_init))

enum {
  PROP_0,

  PROP_CERTIFICATE,
  PROP_ENTITLEMENT,
  PROP_FILE,
  PROP_KEYFILE,

  N_PROPS
};

static GParamSpec *properties [N_PROPS];

/**
 * rhsm_entitlement_certificate_error_quark:
 *
 * Returns: an #GQuark.
 */
G_DEFINE_QUARK (rhsm-entitlement-certificate-error-quark, rhsm_entitlement_certificate_error)

/**
 * rhsm_entitlement_certificate_get_entitlement:
 * @cert: an #RHSMEntitlementCertificate.
 *
 * Returns: (transfer none): an #JsonNode.
 */
JsonNode *
rhsm_entitlement_certificate_get_entitlement (RHSMEntitlementCertificate *cert)
{
  return json_parser_get_root (cert->entitlement_parser);
}

/**
 * rhsm_entitlement_certificate_get_file:
 * @cert: an #RHSMEntitlementCertificate.
 *
 * Returns: (transfer none): path to the certificate.
 */
const gchar *
rhsm_entitlement_certificate_get_file (RHSMEntitlementCertificate *cert)
{
  return cert->file;
}

/**
 * rhsm_entitlement_certificate_get_keyfile:
 * @cert: an #RHSMEntitlementCertificate.
 *
 * Returns: (transfer none): path to the certificate key.
 */
const gchar *
rhsm_entitlement_certificate_get_keyfile (RHSMEntitlementCertificate *cert)
{
  return cert->keyfile;
}

#define ENTITLEMENT_DATA_HEADER "-----BEGIN ENTITLEMENT DATA-----"
#define ENTITLEMENT_DATA_FOOTER "-----END ENTITLEMENT DATA-----"

/*
 * parse_entitlement_data:
 * @data: certificate data.
 * @error: (nullable): an #GError.
 *
 * Returns: a new #JsonParser.
 */
static JsonParser *
parse_entitlement_data (const gchar  *data,
                        GError      **error)
{
  /*
   * Payload stored directly  in a file with a base64-encoded, zlib-compressed
   * JSON blob.
   */

  const gchar *start = g_strstr_len (data, -1, ENTITLEMENT_DATA_HEADER);
  if (start == NULL)
    {
      g_set_error_literal (error,
                           RHSM_ENTITLEMENT_CERTIFICATE_ERROR,
                           RHSM_ENTITLEMENT_CERTIFICATE_ERROR_FAILED,
                           "ENTITLEMENT DATA header can not be found");
      return NULL;
      }
  const gchar *end = g_strstr_len (start, -1, ENTITLEMENT_DATA_FOOTER);
  if (end == NULL)
    {
      g_set_error_literal (error,
                           RHSM_ENTITLEMENT_CERTIFICATE_ERROR,
                           RHSM_ENTITLEMENT_CERTIFICATE_ERROR_FAILED,
                           "ENTITLEMENT DATA footer can not be found");
      return NULL;
    }

  gsize hlen = strlen (ENTITLEMENT_DATA_HEADER);
  gchar *ent = g_strndup (start + hlen, end - start - hlen);

  gsize zlen = 0;
  guchar *zdata = g_base64_decode_inplace (ent, &zlen);
  g_autoptr(GInputStream) zstream = g_memory_input_stream_new_from_data (zdata, zlen, g_free);
  g_autoptr(GZlibDecompressor) decompressor = g_zlib_decompressor_new (G_ZLIB_COMPRESSOR_FORMAT_ZLIB);
  g_autoptr(GInputStream) cstream = g_converter_input_stream_new (zstream, G_CONVERTER (decompressor));
#if JSON_CHECK_VERSION (1, 1, 2)
  g_autoptr(JsonParser) parser = json_parser_new_immutable ();
#else
  g_autoptr(JsonParser) parser = json_parser_new ();
#endif
  if (!json_parser_load_from_stream (parser, cstream, NULL, error))
    return NULL;

  return g_object_ref (parser);
}

/**
 * rhsm_entitlement_certificate_new_from_file:
 * @file: path to the certificate.
 * @error: (nullable): an #GError.
 *
 * Returns: (transfer full): a new #RHSMEntitlementCertificate.
 */
RHSMEntitlementCertificate *
rhsm_entitlement_certificate_new_from_file (const gchar  *file,
                                            GError      **error)
{
  g_autofree gchar *certificate = NULL;
  gsize len = 0;
  if (!g_file_get_contents (file, &certificate, &len, error))
    return NULL;

  return g_initable_new (RHSM_TYPE_ENTITLEMENT_CERTIFICATE,
                         NULL /* cancellable */,
                         error,
                         "certificate", certificate,
                         "file", file,
                         NULL);
}

/**
 * rhsm_entitlement_certificate_discover:
 * @path: (nullable): path where to search for certificates.
 * @error: (nullable): an #GError.
 *
 * Returns: (element-type RHSM.EntitlementCertificate) (transfer full): list of found entitlement certificates.
 */
GPtrArray *
rhsm_entitlement_certificate_discover (const gchar  *path,
                                       GError      **error)
{
  g_autoptr(GError) local_error = NULL;
  g_autoptr(GPtrArray) certs = g_ptr_array_new_with_free_func (g_object_unref);

  if (path == NULL)
    {
      if (g_file_test ("/etc/pki/entitlement-host", G_FILE_TEST_IS_DIR))
        path = "/etc/pki/entitlement-host";
      else
        path = "/etc/pki/entitlement";
    }

  g_autoptr(GDir) dir = g_dir_open (path, 0, error);
  if (dir == NULL)
    return NULL;

  const gchar *fname = NULL;
  while ((fname = g_dir_read_name (dir)) != NULL)
    {
      if (!g_str_has_suffix (fname, ".pem"))
        continue;
      g_autofree gchar *file = g_build_filename (path, fname, NULL);
      RHSMEntitlementCertificate *cert = rhsm_entitlement_certificate_new_from_file (file, NULL);
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
rhsm_entitlement_certificate_finalize (GObject *object)
{
  RHSMEntitlementCertificate *cert = RHSM_ENTITLEMENT_CERTIFICATE (object);

  g_clear_error (&cert->construct_error);

  g_clear_object (&cert->entitlement_parser);

  g_clear_pointer (&cert->file, g_free);
  g_clear_pointer (&cert->keyfile, g_free);

  G_OBJECT_CLASS (rhsm_entitlement_certificate_parent_class)->finalize (object);
}

static void
rhsm_entitlement_certificate_get_property (GObject    *object,
                                           guint       prop_id,
                                           GValue     *value,
                                           GParamSpec *pspec)
{
  RHSMEntitlementCertificate *cert = RHSM_ENTITLEMENT_CERTIFICATE (object);

  switch (prop_id)
    {
    case PROP_ENTITLEMENT:
      g_value_set_boxed (value, json_parser_get_root (cert->entitlement_parser));
      break;

    case PROP_FILE:
      g_value_set_string (value, rhsm_entitlement_certificate_get_file (cert));
      break;

    case PROP_KEYFILE:
      g_value_set_string (value, rhsm_entitlement_certificate_get_keyfile (cert));
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
rhsm_entitlement_certificate_set_property (GObject      *object,
                                           guint         prop_id,
                                           const GValue *value,
                                           GParamSpec   *pspec)
{
  RHSMEntitlementCertificate *cert = RHSM_ENTITLEMENT_CERTIFICATE (object);
  g_autoptr(GError) error = NULL;
  const gchar *cstring = NULL;

  switch (prop_id)
    {
    case PROP_CERTIFICATE:
      cstring = g_value_get_string (value);
      if (cstring == NULL)
        break;
      cert->entitlement_parser = parse_entitlement_data (cstring, &error);
      if (cert->entitlement_parser == NULL && cert->construct_error == NULL)
        cert->construct_error = g_error_copy (error);
      break;

    case PROP_FILE:
      cert->file = g_value_dup_string (value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static gboolean
rhsm_entitlement_certificate_initable_init (GInitable     *initable,
                                            GCancellable  *cancellable,
                                            GError       **error)
{
  RHSMEntitlementCertificate *cert = RHSM_ENTITLEMENT_CERTIFICATE (initable);

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return FALSE;

  if (cert->construct_error != NULL)
    {
      g_propagate_error (error, cert->construct_error);
      cert->construct_error = NULL;
      return FALSE;
    }
  else if (cert->entitlement_parser == NULL)
    {
      g_set_error_literal (error,
                           RHSM_ENTITLEMENT_CERTIFICATE_ERROR,
                           RHSM_ENTITLEMENT_CERTIFICATE_ERROR_FAILED,
                           "No certificate found");
      return FALSE;
    }

  /* By default if cert file is xxx.pem, then keyfile should be xxx-key.pem */
  if (cert->keyfile == NULL)
    {
      const gchar *ext = g_strrstr (cert->file, ".");
      if (ext == NULL)
        {
          g_set_error_literal (error,
                               G_IO_ERROR,
                               G_IO_ERROR_FAILED,
                               "Can't determine extension of the file");
          return FALSE;
        }
      g_autofree gchar *base = g_strndup (cert->file, ext - cert->file);
      cert->keyfile = g_strdup_printf ("%s-key%s", base, ext);
    }

  return TRUE;
}

static void
rhsm_entitlement_certificate_initable_iface_init (GInitableIface *iface)
{
  iface->init = rhsm_entitlement_certificate_initable_init;
}

static void
rhsm_entitlement_certificate_class_init (RHSMEntitlementCertificateClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = rhsm_entitlement_certificate_finalize;
  object_class->get_property = rhsm_entitlement_certificate_get_property;
  object_class->set_property = rhsm_entitlement_certificate_set_property;

  /**
   * RHSMEntitlementCertificate:certificate:
   */
  properties [PROP_CERTIFICATE] =
    g_param_spec_string ("certificate",
                         NULL,
                         NULL,
                         NULL,
                         (G_PARAM_WRITABLE |
                          G_PARAM_CONSTRUCT_ONLY |
                          G_PARAM_STATIC_STRINGS));

  /**
   * RHSMEntitlementCertificate:entitlement:
   */
  properties [PROP_ENTITLEMENT] =
    g_param_spec_boxed ("entitlement",
                        NULL,
                        NULL,
                        JSON_TYPE_NODE,
                        (G_PARAM_READABLE |
                         G_PARAM_STATIC_STRINGS));

  /**
   * RHSMEntitlementCertificate:file:
   */
  properties [PROP_FILE] =
    g_param_spec_string ("file",
                         NULL,
                         NULL,
                         NULL,
                         (G_PARAM_READWRITE |
                          G_PARAM_CONSTRUCT_ONLY |
                          G_PARAM_STATIC_STRINGS));

  /**
   * RHSMEntitlementCertificate:keyfile:
   */
  properties [PROP_KEYFILE] =
    g_param_spec_string ("keyfile",
                         NULL,
                         NULL,
                         NULL,
                         (G_PARAM_READABLE |
                          G_PARAM_STATIC_STRINGS));

  g_object_class_install_properties (object_class, N_PROPS, properties);
}

static void
rhsm_entitlement_certificate_init (RHSMEntitlementCertificate *cert)
{
}
