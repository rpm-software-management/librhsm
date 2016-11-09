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

#pragma once

#if !defined (RHSM_INSIDE) && !defined (RHSM_COMPILATION)
#error "Only <rhsm.h> can be included directly."
#endif

#include <glib-object.h>
#include <gio/gio.h>

G_BEGIN_DECLS

#define RHSM_TYPE_PRODUCT_CERTIFICATE rhsm_product_certificate_get_type ()
G_DECLARE_FINAL_TYPE (RHSMProductCertificate, rhsm_product_certificate, RHSM, PRODUCT_CERTIFICATE, GObject)

/**
 * RHSMProductCertificateError:
 * @RHSM_PRODUCT_CERTIFICATE_ERROR_FAILED:       Generic error.
 * @RHSM_PRODUCT_CERTIFICATE_ERROR_NO_EXTENSION: No required X509 extension.
 */
typedef enum {
  RHSM_PRODUCT_CERTIFICATE_ERROR_FAILED,
  RHSM_PRODUCT_CERTIFICATE_ERROR_NO_EXTENSION
} RHSMProductCertificateError;

#define RHSM_PRODUCT_CERTIFICATE_ERROR rhsm_product_certificate_error_quark ()

RHSMProductCertificate *rhsm_product_certificate_new_from_file (const gchar             *file,
                                                                GError                 **error);
GPtrArray              *rhsm_product_certificate_discover      (const gchar             *path,
                                                                GError                 **error);
GQuark                  rhsm_product_certificate_error_quark   (void);
guint64                 rhsm_product_certificate_get_id        (RHSMProductCertificate  *cert);
const gchar            *rhsm_product_certificate_get_name      (RHSMProductCertificate  *cert);
const gchar            *rhsm_product_certificate_get_version   (RHSMProductCertificate  *cert);
const gchar            *rhsm_product_certificate_get_arch      (RHSMProductCertificate  *cert);
const gchar            *rhsm_product_certificate_get_tags      (RHSMProductCertificate  *cert);

G_END_DECLS
