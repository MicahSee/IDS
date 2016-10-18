#ifndef _SNBUF_LAYOUT_H
#define _SNBUF_LAYOUT_H

#define SNBUF_MBUF 128
#define SNBUF_IMMUTABLE 64
#define SNBUF_METADATA 128
#define SNBUF_SCRATCHPAD 64
#define SNBUF_RESERVE (SNBUF_IMMUTABLE + SNBUF_METADATA + SNBUF_SCRATCHPAD)
#define SNBUF_HEADROOM 128
#define SNBUF_DATA 2048

#define SNBUF_MBUF_OFF 0

#define SNBUF_IMMUTABLE_OFF SNBUF_MBUF

#define SNBUF_METADATA_OFF (SNBUF_IMMUTABLE_OFF + SNBUF_IMMUTABLE)

#define SNBUF_SCRATCHPAD_OFF (SNBUF_METADATA_OFF + SNBUF_METADATA)

#define SNBUF_HEADROOM_OFF (SNBUF_SCRATCHPAD_OFF + SNBUF_SCRATCHPAD)

#define SNBUF_DATA_OFF (SNBUF_HEADROOM_OFF + SNBUF_HEADROOM)

#endif
