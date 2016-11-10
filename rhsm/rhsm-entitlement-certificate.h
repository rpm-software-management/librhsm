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

#pragma once

#if !defined (RHSM_INSIDE) && !defined (RHSM_COMPILATION)
#error "Only <rhsm.h> can be included directly."
#endif

#include <glib-object.h>
#include <json-glib/json-glib.h>

G_BEGIN_DECLS

#define RHSM_TYPE_ENTITLEMENT_CERTIFICATE rhsm_entitlement_certificate_get_type ()
G_DECLARE_FINAL_TYPE (RHSMEntitlementCertificate, rhsm_entitlement_certificate, RHSM, ENTITLEMENT_CERTIFICATE, GObject)

/**
 * RHSMEntitlementCertificateError:
 * @RHSM_ENTITLEMENT_CERTIFICATE_ERROR_FAILED: Generic error.
 */
typedef enum {
  RHSM_ENTITLEMENT_CERTIFICATE_ERROR_FAILED
} RHSMEntitlementCertificateError;

#define RHSM_ENTITLEMENT_CERTIFICATE_ERROR rhsm_entitlement_certificate_error_quark ()

GQuark                      rhsm_entitlement_certificate_error_quark     (void);
RHSMEntitlementCertificate *rhsm_entitlement_certificate_new_from_file   (const gchar                 *file,
                                                                          GError                     **error);
JsonNode                   *rhsm_entitlement_certificate_get_entitlement (RHSMEntitlementCertificate  *cert);
const gchar                *rhsm_entitlement_certificate_get_file        (RHSMEntitlementCertificate  *cert);
const gchar                *rhsm_entitlement_certificate_get_keyfile     (RHSMEntitlementCertificate  *cert);

G_END_DECLS
