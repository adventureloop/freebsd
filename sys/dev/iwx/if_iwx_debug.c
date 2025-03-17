/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2015 Adrian Chadd <adrian@FreeBSD.org>
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Tom Jones <thj@FreeBSD.org> under sponsorship
 * from the FreeBSD Foundation.
 */

#include <sys/param.h>
#include <sys/systm.h>

#include <dev/iwx/if_iwx_debug.h>

/* 
 * Pull in command groups and cmd selectors to avoid pulling in all if iwx_reg.h
 * and if_iwxvar.h.
 */
#define IWX_LEGACY_GROUP		0x0
#define IWX_LONG_GROUP			0x1
#define IWX_SYSTEM_GROUP		0x2
#define IWX_MAC_CONF_GROUP 		0x3
#define IWX_PHY_OPS_GROUP		0x4
#define IWX_DATA_PATH_GROUP		0x5
#define IWX_PROT_OFFLOAD_GROUP  	0xb
#define IWX_REGULATORY_AND_NVM_GROUP	0xc

static inline uint8_t
iwx_cmd_opcode(uint32_t cmdid)
{
        return cmdid & 0xff;
}

static inline uint8_t
iwx_cmd_groupid(uint32_t cmdid)
{
        return ((cmdid & 0Xff00) >> 8);
}

static uint16_t bbl_idx = 0;
static uint32_t bbl_seq = 0;
static uint8_t bbl_compress = 1;


static const char *
iwx_bbl_to_str(int type)
{
	switch(type) {
	case IWX_BBL_PKT_TX:
		return ("IWX_BBL_PKT_TX");
	case IWX_BBL_PKT_RX:
		return ("IWX_BBL_PKT_RX");
	case IWX_BBL_PKT_DUP:
		return ("IWX_BBL_PKT_DUP");
	case IWX_BBL_CMD_TX:
		return ("IWX_BBL_CMD_TX");
	case IWX_BBL_CMD_RX:
		return ("IWX_BBL_CMD_RX");
	case IWX_BBL_ANY:
		return ("IWX_BBL_ANY");
	default:
		return ("ERROR");
	}
}

static const char *
get_label(struct opcode_label *table, uint8_t opcode)
{
	struct opcode_label *op = table;
	while(op->label != NULL) {
		if (op->opcode == opcode)
			return op->label;
		op++;
	}
	return "NOT FOUND IN TABLE";
}

static struct opcode_label *
get_table(uint8_t group)
{
	switch (group)
	{
	case IWX_LEGACY_GROUP:
	case IWX_LONG_GROUP:
		return legacy_opcodes;
		break;
	case IWX_SYSTEM_GROUP:
		return system_opcodes;
		break;
	case IWX_MAC_CONF_GROUP:
		return macconf_opcodes;
		break;
	case IWX_DATA_PATH_GROUP:
		return data_opcodes;
		break;
	case IWX_REGULATORY_AND_NVM_GROUP:
		return reg_opcodes;
		break;
	case IWX_PHY_OPS_GROUP:
		return phyops_opcodes;
		break;
	case IWX_PROT_OFFLOAD_GROUP:
		break;
	}
	return NULL;
}

void
print_opcode(const char *func, int line, int type, uint32_t code)
{
	int print = print_mask & type;
	uint8_t opcode = iwx_cmd_opcode(code);
	uint8_t group = iwx_cmd_groupid(code);

	struct opcode_label *table = get_table(group);
	if (table == NULL) {
		printf("Couldn't find opcode table for 0x%08x", code);
		return;
	}

	for (int i = 0; i < nitems(print_codes); i++)
		if (print_codes[i][0] == group && print_codes[i][1] == opcode)
			print = 1;

	if (print) {
		printf("%s:%d %s\t%s\t%s\t(0x%08x)\n", func, line,
		    iwx_bbl_to_str(type), get_label(command_group, group),
		    get_label(table, opcode), code);
	}
}

void
iwx_dump_cmd(uint32_t id, void *data, uint16_t len, const char *str, int type)
{
	int dump = dump_mask & type;
	uint8_t opcode = iwx_cmd_opcode(id);
	uint8_t group = iwx_cmd_groupid(id);

	for (int i = 0; i < nitems(dump_codes); i++)
		if (dump_codes[i][0] == group && dump_codes[i][1] == opcode)
			dump = 1;

	if (dump)
		hexdump(data, len, str, 0);
}

void 
iwx_bbl_add_entry(uint64_t code, int type, int ticks)
{
	/* 
	 * Compress together repeated notifications, but increment the sequence
	 * number so we can track things processing.
	 */
	if (bbl_compress && (iwx_bb_log[bbl_idx].code == code &&
	    iwx_bb_log[bbl_idx].type == type)) {
		iwx_bb_log[bbl_idx].count++;
		iwx_bb_log[bbl_idx].seq = bbl_seq++;
		iwx_bb_log[bbl_idx].ticks = ticks;
		return;
	}

	if (bbl_idx++ > IWX_BBL_ENTRIES) {
#if 0
		printf("iwx bbl roll over: type %d (%lu)\n", type, code);
#endif
		bbl_idx = 0;	
	}	
	iwx_bb_log[bbl_idx].code = code;
	iwx_bb_log[bbl_idx].type = type;
	iwx_bb_log[bbl_idx].seq = bbl_seq++;
	iwx_bb_log[bbl_idx].ticks = ticks;
	iwx_bb_log[bbl_idx].count = 1;
}

static void
iwx_bbl_print_entry(struct iwx_bbl_entry *e)
{
	uint8_t opcode = iwx_cmd_opcode(e->code);
	uint8_t group = iwx_cmd_groupid(e->code);

	switch(e->type) {
	case IWX_BBL_PKT_TX:
		printf("pkt     ");
		printf("seq %08d\t pkt len %ld",
			e->seq, e->code);
		break;
		printf("pkt dup ");
		printf("seq %08d\t dup count %ld",
			e->seq, e->code);
		break;
	case IWX_BBL_CMD_TX:
		printf("tx ->   ");
		printf("seq %08d\tcode 0x%08lx (%s:%s)",
			e->seq, e->code, get_label(command_group, group),
			get_label(get_table(group), opcode));
		break;
	case IWX_BBL_CMD_RX:
		printf("rx      ");
		printf("seq %08d\tcode 0x%08lx (%s:%s)",
			e->seq, e->code, get_label(command_group, group),
			get_label(get_table(group), opcode));
		break;
	}
	if (e->count > 1)
		printf(" (count %d)", e->count);
	printf("\n");
}

void
iwx_bbl_print_log(void)
{
	int start = -1;

	start = bbl_idx+1;
	if (start > IWX_BBL_ENTRIES-1)
		start = 0;

	for (int i = start; i < IWX_BBL_ENTRIES; i++) {
		struct iwx_bbl_entry *e = &iwx_bb_log[i];
		printf("bbl entry %05d %05d: ", i, e->ticks);
		iwx_bbl_print_entry(e);
	}
	for (int i = 0; i < start; i++) {
		struct iwx_bbl_entry *e = &iwx_bb_log[i];
		printf("bbl entry %05d %05d: ", i, e->ticks);
		iwx_bbl_print_entry(e);
	}
	printf("iwx bblog index %d seq %d\n", bbl_idx, bbl_seq);
}
