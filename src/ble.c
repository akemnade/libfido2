#include "fido.h"
#include "fido/param.h"

#define CTAPBLE_PING 0x81
#define CTAPBLE_KEEPALIVE 0x82
#define CTAPBLE_MSG 0x83
#define CTAPBLE_CANCEL 0xBE
#define CTAPBLE_ERROR 0xBF
#define CTAPBLE_MAX_FRAME_LEN 512
#define CTAPBLE_INIT_HEADER_LEN 3
#define CTAPBLE_CONT_HEADER_LEN 1


#ifndef MIN
#define MIN(x, y) ((x) > (y) ? (y) : (x))
#endif

union frame {
	struct {
		uint8_t cmd;
		uint8_t hlen;
		uint8_t llen;
		uint8_t data[CTAPBLE_MAX_FRAME_LEN - CTAPBLE_INIT_HEADER_LEN];
	} init;
	struct {
		uint8_t seq;
		uint8_t data[CTAPBLE_MAX_FRAME_LEN - CTAPBLE_CONT_HEADER_LEN];
	} cont;
};

static size_t
tx_preamble(fido_dev_t *d, uint8_t cmd, const u_char *buf, size_t count)
{
	union frame frag_buf;
	size_t fragment_len = MIN(fido_ble_get_cp_size(d), CTAPBLE_MAX_FRAME_LEN);
	int r;

	if (fragment_len <= CTAPBLE_INIT_HEADER_LEN)
		return 0;

	frag_buf.init.cmd = cmd;
	frag_buf.init.hlen = (count >> 8) & 0xff;
	frag_buf.init.llen = count & 0xff;

	count = MIN(count, fragment_len - CTAPBLE_INIT_HEADER_LEN);
	memcpy(frag_buf.init.data, buf, count);

	count += CTAPBLE_INIT_HEADER_LEN;
	r = d->io.write(d->io_handle, (const u_char *)&frag_buf, count);
	explicit_bzero(&frag_buf, sizeof(frag_buf));

	if ((r < 0) || ((size_t)r != count))
		return 0;

	return count - CTAPBLE_INIT_HEADER_LEN;
}

static size_t
tx_cont(fido_dev_t *d, uint8_t seq, const u_char *buf, size_t count)
{
	union frame frag_buf;
	int r;
	size_t fragment_len = MIN(fido_ble_get_cp_size(d), CTAPBLE_MAX_FRAME_LEN);

	if (fragment_len <= CTAPBLE_CONT_HEADER_LEN)
		return 0;

	frag_buf.cont.seq = seq;
	count = MIN(count, fragment_len - CTAPBLE_CONT_HEADER_LEN);
	memcpy(frag_buf.cont.data, buf, count);

	count += CTAPBLE_CONT_HEADER_LEN;
	r = d->io.write(d->io_handle, (const u_char *)&frag_buf, count);
	explicit_bzero(&frag_buf, sizeof(frag_buf));

	if ((r < 0) || ((size_t)r != count))
		return 0;

	return count - CTAPBLE_CONT_HEADER_LEN;
}

static int
fido_ble_fragment_tx(fido_dev_t *d, uint8_t cmd, const u_char *buf, size_t count)
{
	size_t n, sent;

	if ((sent = tx_preamble(d, cmd, buf, count)) == 0) {
		fido_log_debug("%s: tx_preamble", __func__);
		return (-1);
	}

	for (uint8_t seq = 0; sent < count; sent += n) {
		if ((n = tx_cont(d, seq++, buf + sent, count - sent)) == 0) {
			fido_log_debug("%s: tx_frame", __func__);
			return (-1);
		}

		seq &= 0x7f;
	}

	return 0;
}

int
fido_ble_tx(fido_dev_t *d, uint8_t cmd, const u_char *buf, size_t count)
{
	switch(cmd) {
		case CTAP_CMD_INIT:
			return FIDO_OK;
		case CTAP_CMD_CBOR:
		case CTAP_CMD_MSG:
			return fido_ble_fragment_tx(d, CTAPBLE_MSG, buf, count);
	}

	return FIDO_ERR_INTERNAL;
}

static int
rx_init(fido_dev_t *d, unsigned char *buf, size_t count, int ms)
{
	(void)ms;
	fido_ctap_info_t *attr = (fido_ctap_info_t *)buf;
	if (count != sizeof(*attr)) {
		fido_log_debug("%s: count=%zu", __func__, count);
		return -1;
	}

	memset(attr, 0, sizeof(*attr));

	/* we allow only FIDO2 devices for now for simplicity */
	attr->flags = FIDO_CAP_CBOR | FIDO_CAP_NMSG;
	memcpy(&attr->nonce, &d->nonce, sizeof(attr->nonce));

	return (int)count;
}

static int
rx_fragments(fido_dev_t *d, unsigned char *buf, size_t count, int ms)
{
	size_t fragment_len = fido_ble_get_cp_size(d);
	uint8_t *reply;
	uint8_t seq;
	size_t payload;
	size_t reply_length;
	int ret;
	if (fragment_len <= 3) {
		return -1;
	}
	reply = calloc(1, fragment_len);
	payload = fragment_len - 3;
	if (count < payload)
		payload = count;

	do {
		ret = d->io.read(d->io_handle, reply, payload + 3, ms);
		if (ret <= 0)
			goto out;
	} while (reply[0] == CTAPBLE_KEEPALIVE);

	if ((reply[0] != CTAPBLE_MSG) || (ret <= 3)) {
		ret = -1;
		goto out;
	}
	ret -= 3;

	reply_length = ((size_t)reply[1]) << 8 | reply[2];
	if (reply_length > count)
		reply_length = count;

	if (reply_length < count)
		count = reply_length;

	memcpy(buf, reply + 3, (size_t)ret);
	count -= (size_t)ret;
	buf += ret;
	seq = 0;

	while(count > 0) {
		payload = fragment_len - 1;
		if (count < payload)
			payload = count;

		ret = d->io.read(d->io_handle, reply, payload + 1, ms);
		if (ret <= 1) {
			if (ret >= 0)
				ret = -1;
			goto out;
		}
		ret--;
		if (reply[0] != seq) {
			ret = -1;
			goto out;
		}
		memcpy(buf, reply + 1, (size_t) ret);

		seq++;
		count -= (size_t) ret;
		buf += ret;
	}
	ret = (int)reply_length;
out:
	explicit_bzero(reply, fragment_len);
	free(reply);
	return ret;
}

int
fido_ble_rx(fido_dev_t *d, uint8_t cmd, u_char *buf, size_t count, int ms)
{
	switch(cmd) {
		case CTAP_CMD_INIT:
			return rx_init(d, buf, count, ms);
		case CTAP_CMD_CBOR:
			return rx_fragments(d, buf, count, ms);
		default:
			return FIDO_ERR_INTERNAL;
	}
}

bool
fido_is_ble(const char *path)
{
	return !strncmp(path, FIDO_BLE_PREFIX, strlen(FIDO_BLE_PREFIX));
}

int
fido_dev_set_ble(fido_dev_t *d)
{
	if (d->io_handle != NULL) {
		fido_log_debug("%s: device open", __func__);
		return -1;
	}
	d->io_own = true;
	d->io = (fido_dev_io_t) {
		fido_ble_open,
		fido_ble_close,
		fido_ble_read,
		fido_ble_write,
	};
	d->transport = (fido_dev_transport_t) {
		fido_ble_rx,
		fido_ble_tx,
	};

	return 0;
}

