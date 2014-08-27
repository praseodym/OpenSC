/*
 * card-pkiappet.c: Support for PKIapplet (javacardsign applet) cards.
 *
 * Copyright (C) 2014 Mark Janssen <mark@praseodym.net>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "config.h"

#include <string.h>

#include "internal.h"
#include "cardctl.h"

static struct sc_atr_table pkiapplet_atrs[] = {
	{"3b:f8:13:00:00:81:31:fe:45:4a:43:4f:50:76:32:34:31:b7", NULL, NULL,
	 SC_CARD_TYPE_PKIAPPLET, 0, NULL},
	{NULL, NULL, NULL, 0, 0, NULL}
};

static struct sc_card_operations *iso_ops;
static struct sc_card_operations pkiapplet_ops;
static struct sc_card_driver pkiapplet_drv = {
	"PKIapplet (javacardsign applet) card",
	"pkiapplet",
	&pkiapplet_ops,
	NULL, 0, NULL
};

static int pkiapplet_match_card(sc_card_t * card)
{
	int i;
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	i = _sc_match_atr(card, pkiapplet_atrs, &card->type);
	if (i < 0)
		return 0;
	return 1;
}

static int select_pkcs15_app(sc_card_t * card)
{
	sc_path_t app;
	int r;

	/* Regular PKCS#15 AID */
	sc_format_path("A000000063504B43532D3135", &app);
	app.type = SC_PATH_TYPE_DF_NAME;
	r = sc_select_file(card, &app, NULL);
	if (r != SC_SUCCESS) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "unable to select PKCS15 applet");
		return r;
	}

	return SC_SUCCESS;
}

static int pkiapplet_init(sc_card_t * card)
{
	unsigned int flags;
	int r;
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	card->name = "pkiapplet";
	card->cla  = 0x00;
	card->drv_data = NULL;

	flags =SC_ALGORITHM_ONBOARD_KEY_GEN
		 | SC_ALGORITHM_RSA_RAW
		 | SC_ALGORITHM_RSA_HASH_NONE;

	_sc_card_add_rsa_alg(card, 1024, flags, 0);

	card->caps = SC_CARD_CAP_RNG;

	/* we need read_binary&friends with max 224 bytes per read */
	card->max_send_size = 255;
	card->max_recv_size = 255;

	r = select_pkcs15_app(card);
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

static struct sc_card_driver *sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	if (iso_ops == NULL)
		iso_ops = iso_drv->ops;

	pkiapplet_ops = *iso_ops;
	pkiapplet_ops.match_card = pkiapplet_match_card;
	pkiapplet_ops.init = pkiapplet_init;

#if 0
    /* iso7816-4 functions */
    pkiapplet_ops.read_binary   = pkiapplet_read_binary;
    pkiapplet_ops.write_binary  = NULL;
    pkiapplet_ops.update_binary = pkiapplet_update_binary;

    /* iso7816-8 functions */
    pkiapplet_ops.restore_security_env = pkiapplet_restore_security_env;
    pkiapplet_ops.set_security_env  = pkiapplet_set_security_env;
    pkiapplet_ops.decipher = pkiapplet_decipher;
    pkiapplet_ops.compute_signature = pkiapplet_compute_signature;

    /* iso7816-9 functions */
    pkiapplet_ops.pin_cmd = pkiapplet_pin_cmd;
#endif

	return &pkiapplet_drv;
}

struct sc_card_driver *sc_get_pkiapplet_driver(void)
{
	return sc_get_driver();
}
