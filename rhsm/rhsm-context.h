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

G_BEGIN_DECLS

#define RHSM_TYPE_CONTEXT rhsm_context_get_type ()
G_DECLARE_FINAL_TYPE (RHSMContext, rhsm_context, RHSM, CONTEXT, GObject)

RHSMContext *rhsm_context_new                          (void);
const gchar *rhsm_context_get_arch                     (RHSMContext *ctx);
void         rhsm_context_set_arch                     (RHSMContext *ctx,
                                                        const gchar *arch);
const gchar *rhsm_context_get_conf_file                (RHSMContext *ctx);
const gchar *rhsm_context_get_baseurl                  (RHSMContext *ctx);
void         rhsm_context_set_baseurl                  (RHSMContext *ctx,
                                                        const gchar *baseurl);
const gchar *rhsm_context_get_ca_cert_dir              (RHSMContext *ctx);
void         rhsm_context_set_ca_cert_dir              (RHSMContext *ctx,
                                                        const gchar *ca_cert_dir);
const gchar *rhsm_context_get_repo_ca_cert             (RHSMContext *ctx);
void         rhsm_context_set_repo_ca_cert             (RHSMContext *ctx,
                                                        const gchar *repo_ca_cert);
const gchar *rhsm_context_get_product_cert_dir         (RHSMContext *ctx);
void         rhsm_context_set_product_cert_dir         (RHSMContext *ctx,
                                                        const gchar *product_cert_dir);
const gchar *rhsm_context_get_entitlement_cert_dir     (RHSMContext *ctx);
void         rhsm_context_set_entitlement_cert_dir     (RHSMContext *ctx,
                                                        const gchar *entitlement_cert_dir);
GPtrArray   *rhsm_context_get_product_certificates     (RHSMContext *ctx);
GPtrArray   *rhsm_context_get_entitlement_certificates (RHSMContext *ctx);
