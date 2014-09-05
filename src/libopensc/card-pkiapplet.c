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

#include <time.h>
static long t1, t2, tot_read = 0, tot_dur = 0, dur;

#define PKIAPPLET_MAX_FILE_SIZE		65535

/* Used for a trick in select file and read binary */
static size_t next_idx = (size_t)-1;

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
	// sc_select_file doesn't work with our overriden pkiapplet_select_file
	r =  sc_get_iso7816_driver()->ops->select_file(card, &app, NULL);
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
		 | SC_ALGORITHM_RSA_HASH_NONE
		 | SC_ALGORITHM_RSA_HASH_SHA1
		 | SC_ALGORITHM_RSA_HASH_SHA256;

	_sc_card_add_rsa_alg(card, 1024, flags, 0);

	card->caps = SC_CARD_CAP_RNG;

	/* we need read_binary&friends with max 224 bytes per read */
	card->max_send_size = 255;
	card->max_recv_size = 255;

	r = select_pkcs15_app(card);
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}



static int pkiapplet_select_file(sc_card_t *card, sc_path_t *in_path, sc_file_t **file_out)
{
	sc_apdu_t apdu;
	u8 pathbuf[SC_MAX_PATH_SIZE], *path = pathbuf;
	int r;
	unsigned int pathlen, i;
	char p1;
	sc_file_t *file = NULL;

	assert(card != NULL && in_path != NULL);

	// Standard says we should have "Path without the MF identifier" (ISO7816-4:2005 Table 39)
	// but OpenSC always constructs path with MF prefixed (3F00)
	// TODO: filesystem layout?
	if (in_path->value[0] == 0x3F && in_path->value[1] == 0x00) {
		if (in_path->len > 2) {
			p1 = 0x08;
			// Strip 3F00 prefix from path value
			in_path->len = in_path->len - 2;
			for (i = 0; i < in_path->len; i++) {
				in_path->value[i] = in_path->value[i+2];
			}
		}
		else {
			// opensc-explorer selects 3F00; need to request by FID.
			p1 = 0x00;
		}
	}
	else {
		p1 = 0x08;
	}

	memcpy(path, in_path->value, in_path->len);
	pathlen = in_path->len;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, p1, 0x0C);

	apdu.lc = pathlen;
	apdu.data = path;
	apdu.datalen = pathlen;

	apdu.resplen = 0;
	apdu.le = 0;

	r = sc_transmit_apdu(card, &apdu);

	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Select File APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);

	next_idx = (size_t)-1;		/* reset */

	if (file_out != NULL) {
		file = sc_file_new();
		file->path = *in_path;
		if (pathlen >= 2)
			file->id = (in_path->value[pathlen - 2] << 8) | in_path->value[pathlen - 1];
		file->size = PKIAPPLET_MAX_FILE_SIZE;
		file->shareable = 1;
		file->ef_structure = SC_FILE_EF_TRANSPARENT;
		if (pathlen == 2 && memcmp("\x3F\x00", in_path->value, 2) == 0)
			file->type = SC_FILE_TYPE_DF;
		else
			file->type = SC_FILE_TYPE_WORKING_EF;
		*file_out = file;
	}

	return 0;
}

static int pkiapplet_read_binary(sc_card_t *card,
			      unsigned int idx, u8 * buf, size_t count, unsigned long flags)
{
	int r;

	if (next_idx == idx)
		return 0;	/* File was already read entirely */

	t1 = clock();
	r = iso_ops->read_binary(card, idx, buf, count, flags);
	t2 = clock();

	/* If the 'next_idx trick' shouldn't work, we hope this error
	 * means that an attempt was made to read beyond the file's
	 * contents, so we'll return 0 to end the loop in sc_read_binary()*/
	if (r == SC_ERROR_INCORRECT_PARAMETERS)
		return 0;

	if (r >= 0 && (size_t)r < count)
		next_idx = idx + (size_t)r;

	dur = t2 - t1;
	tot_dur += dur;
	tot_read += r;
#if 0
	printf("%d bytes: %d ms - %d bytes total: %d ms\n", r, dur, tot_read, tot_dur);
#endif
	return r;
}

static struct sc_card_driver *sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	if (iso_ops == NULL)
		iso_ops = iso_drv->ops;

	pkiapplet_ops = *iso_ops;
	pkiapplet_ops.match_card = pkiapplet_match_card;
	pkiapplet_ops.init = pkiapplet_init;

    /* iso7816-4 functions */
    pkiapplet_ops.read_binary   = pkiapplet_read_binary;
    pkiapplet_ops.select_file   = pkiapplet_select_file;

#if 0
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
