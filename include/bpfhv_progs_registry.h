/*
 * This header-only module is used to take trace of all the possible BPFHV programs, they index and
 * thir name
 */


#ifndef __BPFHV_PROGS_REGISTRY_H__
#define __BPFHV_PROGS_REGISTRY_H__


enum {
	BPFHV_PROG_NONE = 0,
	BPFHV_PROG_RX_PUBLISH,
	BPFHV_PROG_RX_COMPLETE,
	BPFHV_PROG_RX_INTRS,
	BPFHV_PROG_RX_RECLAIM,
	BPFHV_PROG_RX_POSTPROC,
	BPFHV_PROG_TX_PUBLISH,
	BPFHV_PROG_TX_COMPLETE,
	BPFHV_PROG_TX_INTRS,
	BPFHV_PROG_TX_RECLAIM,
	BPFHV_PROG_TX_PREPROC,
	BPFHV_PROG_SOCKET_RELEASED,
	BPFHV_PROG_SOCKET_READ,
	BPFHV_PROG_EXTRA_0,
	BPFHV_PROG_EXTRA_1,
	BPFHV_PROG_EXTRA_2,
	BPFHV_PROG_EXTRA_3,
	BPFHV_PROG_EXTRA_4,
	BPFHV_PROG_EXTRA_5,
	BPFHV_PROG_EXTRA_6,
	BPFHV_PROG_EXTRA_7,
	BPFHV_PROG_PROG_DATA,
	BPFHV_PROG_MAX
};


static inline bool
prog_is_optional(unsigned int prog_idx)
{
	return prog_idx == BPFHV_PROG_RX_POSTPROC ||
	       prog_idx == BPFHV_PROG_TX_PREPROC ||
		   (prog_idx >= BPFHV_PROG_SOCKET_RELEASED && prog_idx < BPFHV_PROG_MAX);
}

static inline const char *
progname_from_idx(unsigned int prog_idx)
{
	switch (prog_idx) {
	case BPFHV_PROG_RX_PUBLISH:
		return "rxp";
	case BPFHV_PROG_RX_COMPLETE:
		return "rxc";
	case BPFHV_PROG_RX_INTRS:
		return "rxi";
	case BPFHV_PROG_RX_RECLAIM:
		return "rxr";
	case BPFHV_PROG_RX_POSTPROC:
		return "rxh";
	case BPFHV_PROG_TX_PUBLISH:
		return "txp";
	case BPFHV_PROG_TX_COMPLETE:
		return "txc";
	case BPFHV_PROG_TX_INTRS:
		return "txi";
	case BPFHV_PROG_TX_RECLAIM:
		return "txr";
	case BPFHV_PROG_TX_PREPROC:
		return "txh";
    case BPFHV_PROG_SOCKET_RELEASED:
		return "srl";
	case BPFHV_PROG_SOCKET_READ:
		return "srd";
	case BPFHV_PROG_EXTRA_0:
		return "extra0";
	case BPFHV_PROG_EXTRA_1:
		return "extra1";
	case BPFHV_PROG_EXTRA_2:
		return "extra2";
	case BPFHV_PROG_EXTRA_3:
		return "extra3";
	case BPFHV_PROG_EXTRA_4:
		return "extra4";
	case BPFHV_PROG_EXTRA_5:
		return "extra5";
	case BPFHV_PROG_EXTRA_6:
		return "extra6";
	case BPFHV_PROG_EXTRA_7:
		return "extra7";
	case BPFHV_PROG_PROG_DATA:
		return "pdt";
	default:
		break;
	}

	return NULL;
}


#endif
