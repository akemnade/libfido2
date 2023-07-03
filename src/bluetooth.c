#include "fido.h"
#include "fido/param.h"

#define CTAPBLE_PING 0x81
#define CTAPBLE_KEEPALIVE 0x82
#define CTAPBLE_MSG 0x83
#define CTAPBLE_CANCEL 0xBE
#define CTAPBLE_ERROR 0xBF

static int
fido_bluetooth_fragment_tx(fido_dev_t *d, uint8_t cmd, const u_char *buf, size_t count)
{
	size_t fragment_len = fido_bluetooth_get_cp_size(d);
	u_char *frag_buf;
	size_t payload;
	uint8_t seqnum;

	if (fragment_len <= 3)
		return -1;

	payload = fragment_len - 3;
	frag_buf = calloc(1, fragment_len);
	if (!frag_buf)
		return -1;

	frag_buf[0] = cmd;
	frag_buf[1] = (count >> 8) & 0xff;
	frag_buf[2] = count & 0xff;
	if (payload > count)
		payload = count;

	memcpy(frag_buf + 3, buf, payload);
	d->io.write(d->io_handle, frag_buf, payload + 3);

	count -= payload;
	seqnum = 0;
	buf += payload;
	while (count > 0) {
		payload = fragment_len - 1;
		if (payload > count)
			payload = count;

		memcpy(frag_buf + 1, buf, payload);
		frag_buf[0] = seqnum;
		if (d->io.write(d->io_handle, frag_buf, payload + 1) < 0)
			break;

		count -= payload;
		buf += payload;
		seqnum++;
		seqnum &= 0x7F;
	}

	free(frag_buf);

	if (count > 0)
		return -1;

	return 0;
}

int
fido_bluetooth_tx(fido_dev_t *d, uint8_t cmd, const u_char *buf, size_t count)
{
	switch(cmd) {
		case CTAP_CMD_INIT:
			return FIDO_OK;
		case CTAP_CMD_CBOR:
		case CTAP_CMD_MSG:
			return fido_bluetooth_fragment_tx(d, CTAPBLE_MSG, buf, count);
			break;
	}
	if (cmd == CTAP_CMD_INIT)
		return FIDO_OK;


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
	size_t fragment_len = fido_bluetooth_get_cp_size(d);
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
fido_bluetooth_rx(fido_dev_t *d, uint8_t cmd, u_char *buf, size_t count, int ms)
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
fido_is_bluetooth(const char *path)
{
	return !strncmp(path, FIDO_BLE_PREFIX, strlen(FIDO_BLE_PREFIX));
}

int
fido_dev_set_bluetooth(fido_dev_t *d)
{
	if (d->io_handle != NULL) {
		fido_log_debug("%s: device open", __func__);
		return -1;
	}
	d->io_own = true;
	d->io = (fido_dev_io_t) {
		fido_bluetooth_open,
		fido_bluetooth_close,
		fido_bluetooth_read,
		fido_bluetooth_write,
	};
	d->transport = (fido_dev_transport_t) {
		fido_bluetooth_rx,
		fido_bluetooth_tx,
	};

	return 0;
}

