/* PKIapplet PKCS#15 initialisation
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "internal.h"
#include "pkcs15.h"
#include "cardctl.h"

#define MANU_ID		"pkiapplet"

int sc_pkcs15emu_pkiapplet_init_ex(sc_pkcs15_card_t *, sc_pkcs15emu_opt_t *);

static int pkiapplet_detect_card( sc_pkcs15_card_t *p15card)
{
	sc_card_t *card = p15card->card;

	//fprintf(stderr, "\nPKCS15 DETECT PKIAPPLET\n\n");

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* check if we have the correct card OS */
	if (strcmp(card->name, "pkiapplet"))
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_WRONG_CARD);

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_SUCCESS);
}

static int sc_pkcs15emu_pkiapplet_init( sc_pkcs15_card_t *p15card)
{
	sc_card_t *card = p15card->card;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	//fprintf(stderr, "\nPKCS15 INIT PKIAPPLET\n\n");

	if (p15card->tokeninfo->label)
		free(p15card->tokeninfo->label);
	p15card->tokeninfo->label = malloc(strlen(MANU_ID) + 1);
	if (!p15card->tokeninfo->label)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);
	strcpy(p15card->tokeninfo->label, MANU_ID);

	if (p15card->tokeninfo->manufacturer_id)
		free(p15card->tokeninfo->manufacturer_id);
	p15card->tokeninfo->manufacturer_id = malloc(strlen(MANU_ID) + 1);
	if (!p15card->tokeninfo->manufacturer_id)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);
	strcpy(p15card->tokeninfo->manufacturer_id, MANU_ID);

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_SUCCESS);
}

int sc_pkcs15emu_pkiapplet_init_ex(sc_pkcs15_card_t *p15card,
				  sc_pkcs15emu_opt_t *opts)
{
	SC_FUNC_CALLED(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE);
	
	//fprintf(stderr, "\nPKCS15 INITEX PKIAPPLET\n\n");

	if (opts && opts->flags & SC_PKCS15EMU_FLAGS_NO_CHECK)
		return sc_pkcs15emu_pkiapplet_init(p15card);
	else {
		int r = pkiapplet_detect_card(p15card);
		if (r)
			return SC_ERROR_WRONG_CARD;
		return sc_pkcs15emu_pkiapplet_init(p15card);
	}
}
