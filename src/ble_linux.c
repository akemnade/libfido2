#include <sys/types.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-bus-vtable.h>
#include <unistd.h>

#include "fido.h"
#include "fido/param.h"

#define FIDO_SERVICE_UUID "0000fffd-0000-1000-8000-00805f9b34fb"
#define FIDO_STATUS_UUID  "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb"
#define FIDO_CONTROL_POINT_UUID "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb"
#define FIDO_CONTROL_POINT_LENGTH_UUID "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb"
#define FIDO_SERVICE_REVISION_UUID "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb"

#define DBUS_CHAR_IFACE "org.bluez.GattCharacteristic1"
#define DBUS_DEV_IFACE "org.bluez.Device1"
#define DBUS_SERVICE_IFACE "org.bluez.GattService1"
#define DBUS_PROFILE_IFACE "org.bluez.GattProfile1"
#define DBUS_ADAPTER_IFACE "org.bluez.Adapter1"
#define DBUS_GATTMANAGER_IFACE "org.bluez.GattManager1"

static bool ble_fido_is_useable_device(const char *iface, sd_bus_message * reply, const char **name);
struct ble {
	sd_bus *bus;
	struct {
		char *dev;
		char *service;
		char *status;
		char *control_point;
		char *control_point_length;
		char *service_revision;
	} paths;
	size_t controlpoint_size;
	int status_fd;
};

struct manifest_ctx {
	sd_bus *bus;
	fido_dev_info_t *devlist;
	size_t ilen;
	size_t *olen;
};

static int
found_gatt_characteristic(struct ble *dev, const char *path, sd_bus_message *reply)
{
	bool matches = false;
	bool status_found = false;
	bool control_point_found = false;
	bool control_point_length_found = false;
	bool service_revision_found = false;

	if (!dev->paths.service) {
		if (sd_bus_message_skip(reply, "a{sv}") < 0)
			return -1;

		return 0;
	}
	if (sd_bus_message_enter_container(reply, 'a', "{sv}") < 0)
		return -1;

	while (sd_bus_message_enter_container(reply, 'e', "sv") > 0) {
		const char *prop;
		int r = sd_bus_message_read_basic(reply, 's', &prop);
		if (r < 0)
			return -1;

		if (r == 0)
			continue;

		if (!strcmp(prop, "Service")) {
			const char *devpath;
			if (sd_bus_message_read(reply, "v", "o", &devpath) <= 0)
				return -1;

			if (!strcmp(devpath, dev->paths.service))
				matches = true;

		} else if (!strcmp(prop, "UUID")) {
			const char *uuid;
			if (sd_bus_message_read(reply, "v", "s", &uuid) <= 0)
				return -1;

			if (!strcmp(uuid, FIDO_STATUS_UUID))
				status_found = true;
			if (!strcmp(uuid, FIDO_CONTROL_POINT_UUID))
				control_point_found = true;
			if (!strcmp(uuid, FIDO_CONTROL_POINT_LENGTH_UUID))
				control_point_length_found = true;
			if (!strcmp(uuid, FIDO_SERVICE_REVISION_UUID))
				service_revision_found = true;
		} else {
			if (sd_bus_message_skip(reply, "v") < 0)
				return -1;
		}
		if (sd_bus_message_exit_container(reply) < 0)
			return -1;
	}
	if (sd_bus_message_exit_container(reply) < 0)
		return -1;

	if (!matches)
		return 0;

	if (status_found)
		dev->paths.status = strdup(path);

	if (control_point_found)
		dev->paths.control_point = strdup(path);

	if (control_point_length_found)
		dev->paths.control_point_length = strdup(path);

	if (service_revision_found)
		dev->paths.service_revision = strdup(path);

	return 0;
}

static int
found_gatt_service(struct ble *dev, const char *path, sd_bus_message *reply)
{
	bool matches = false;
	bool service_found = false;
	if (sd_bus_message_enter_container(reply, 'a', "{sv}") < 0)
		return -1;

	while (sd_bus_message_enter_container(reply, 'e', "sv") > 0) {
		const char *prop;
		int r = sd_bus_message_read_basic(reply, 's', &prop);
		if (r < 0)
			return -1;

		if (r == 0)
			continue;

		if (!strcmp(prop, "Device")) {
			const char *devpath;
			if (sd_bus_message_read(reply, "v", "o", &devpath) < 0)
				return -1;

			if (!strcmp(devpath, dev->paths.dev))
				matches = true;

		} else if (!strcmp(prop, "UUID")) {
			const char *uuid;
			if (sd_bus_message_read(reply, "v", "s", &uuid) < 0)
				return -1;

			if (!strcmp(uuid, FIDO_SERVICE_UUID))
				service_found = true;
		} else {
			if (sd_bus_message_skip(reply, "v") < 0)
				return -1;
		}
		if (sd_bus_message_exit_container(reply) < 0)
			return -1;
	}
	if (sd_bus_message_exit_container(reply) < 0)
		return -1;

	if (matches && service_found) {
		dev->paths.service = strdup(path);
	}
	return 0;
}

static int
collect_device_chars(void *data, const char *path, sd_bus_message *reply)
{
	struct ble *dev = (struct ble *)data;
	const char *iface;
	if (sd_bus_message_read_basic(reply, 's', &iface) < 0)
		return -1;

	if (!strcmp(iface, DBUS_SERVICE_IFACE))
		return found_gatt_service(dev, path, reply);

	if (!strcmp(iface, DBUS_CHAR_IFACE))
		return found_gatt_characteristic(dev, path, reply);

	return sd_bus_message_skip(reply, "a{sv}") < 0 ? -1 : 0;
}

static int iterate_over_all_objs(sd_bus_message *reply,
				  int (*new_dbus_interface)(void *,
				  const char *,
				  sd_bus_message *), void *data)
{
	if (sd_bus_message_enter_container(reply, 'a', "{oa{sa{sv}}}") <= 0)
		return -1;

	while (sd_bus_message_enter_container(reply, 'e', "oa{sa{sv}}") > 0) {
		const char *ifacepath = NULL;
		if (sd_bus_message_read_basic(reply, 'o', &ifacepath) <= 0)
			return -1;

		if (sd_bus_message_enter_container(reply, 'a', "{sa{sv}}") < 0)
			return -1;
		while (sd_bus_message_enter_container(reply, 'e', "sa{sv}") > 0) {
			new_dbus_interface(data, ifacepath, reply);
			if (sd_bus_message_exit_container(reply) < 0)
				return -1;
		}
		if (sd_bus_message_exit_container(reply) < 0)
			return -1;

		if (sd_bus_message_exit_container(reply) < 0)
			return -1;
	}
	return 0;
}

void *
fido_ble_open(const char *path)
{
	struct ble *dev;
	sd_bus_message *reply = NULL;
	int ret;
	if (!fido_is_ble(path))
		return NULL;

	path += strlen(FIDO_BLE_PREFIX);

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return NULL;

	dev->status_fd = -1;
	dev->paths.dev = strdup(path);
	if (!dev->paths.dev)
		goto out;

	if (sd_bus_default_system(&dev->bus) < 0)
		goto out;

	if (sd_bus_call_method(dev->bus, "org.bluez",
	    path, "org.freedesktop.DBus.Properties", "GetAll", NULL, &reply,
	    "s", DBUS_DEV_IFACE) < 0)
		goto out;

	if (!ble_fido_is_useable_device(DBUS_DEV_IFACE, reply, NULL))
		goto out;

	sd_bus_message_unref(reply);
	reply = NULL;
	ret = sd_bus_call_method(dev->bus, "org.bluez", "/", "org.freedesktop.DBus.ObjectManager", "GetManagedObjects", NULL, &reply, "");
	if (ret <= 0)
		goto out;

	sd_bus_message_rewind(reply, 1);
	if (iterate_over_all_objs(reply, collect_device_chars, dev) < 0)
		goto out;

	sd_bus_message_unref(reply);
	reply = NULL;

	if (dev->paths.status &&
	    dev->paths.control_point &&
	    dev->paths.control_point_length &&
	    dev->paths.service_revision) {
		uint8_t cp_len[2];
		uint8_t revision;
		if (sd_bus_call_method(dev->bus, "org.bluez", dev->paths.control_point_length,
				       DBUS_CHAR_IFACE, "ReadValue", NULL, &reply, "a{sv}", 0) < 0)
			goto out;

		if (sd_bus_message_read(reply, "ay", 2, cp_len, cp_len + 1) < 0)
			goto out;

		sd_bus_message_unref(reply);
		reply = NULL;

		if (sd_bus_call_method(dev->bus, "org.bluez", dev->paths.service_revision,
				       DBUS_CHAR_IFACE, "ReadValue", NULL, &reply, "a{sv}", 0) < 0)
			goto out;
		if (sd_bus_message_read(reply, "ay", 1, &revision) < 0)
			goto out;

		/* for simplicity, we allow now only FIDO2 */
		if (!(revision & 0x20))
			goto out;

		if (sd_bus_call_method(dev->bus, "org.bluez", dev->paths.service_revision,
				       DBUS_CHAR_IFACE, "WriteValue", NULL, NULL, "aya{sv}", 1, 0x20, 0) < 0)
			goto out;

		dev->controlpoint_size = ((size_t)cp_len[0] << 8) + cp_len[1];
		if (sd_bus_call_method(dev->bus, "org.bluez", dev->paths.status,
				       DBUS_CHAR_IFACE, "AcquireNotify", NULL, &reply, "a{sv}", 0) < 0)
			goto out;

		sd_bus_message_rewind(reply, 1);
		if (sd_bus_message_read_basic(reply, 'h', &dev->status_fd) < 0)
			goto out;
		return dev;
	}
out:
	if (reply)
		sd_bus_message_unref(reply);

	fido_ble_close(dev);
	return NULL;
}

void fido_ble_close(void *handle)
{
	struct ble *dev = (struct ble *)handle;
	if (dev->status_fd >= 0)
		close(dev->status_fd);
	free(dev->paths.service_revision);
	free(dev->paths.control_point_length);
	free(dev->paths.control_point);
	free(dev->paths.service);
	free(dev->paths.dev);
	if (dev->bus)
		sd_bus_unref(dev->bus);

	free(dev);
}

int
fido_ble_read(void *handle, unsigned char *buf, size_t len, int ms)
{
	struct ble *dev = (struct ble *)handle;
	ssize_t r;
	if (fido_hid_unix_wait(dev->status_fd, ms, NULL) < 0)
		return -1;

	r = read(dev->status_fd, buf, len);
	if ((size_t)r != len)
		return -1;

	return (int)r;
}

int
fido_ble_write(void *handle, const unsigned char *buf, size_t len)
{
	struct ble *dev = (struct ble *)handle;
	sd_bus_message *send_msg;
	int r = sd_bus_message_new_method_call(dev->bus, &send_msg, "org.bluez",
					       dev->paths.control_point,
					       DBUS_CHAR_IFACE, "WriteValue");
	if (r < 0)
		goto out;

	r = sd_bus_message_append_array(send_msg, 'y', buf, len);
	if (r < 0)
		goto out;

	r = sd_bus_message_append(send_msg, "a{sv}", 0);
	if (r < 0)
		goto out;

	r = sd_bus_call(dev->bus, send_msg, 0, NULL, NULL);
out:
	sd_bus_message_unref(send_msg);

	return (r >= 0) ? (int)len : -1;
}

size_t
fido_ble_get_cp_size(fido_dev_t *d)
{
	return ((struct ble *)d->io_handle)->controlpoint_size;
}


static bool
ble_fido_is_useable_device(const char *iface, sd_bus_message * reply, const char **name)
{
	int ret;
	bool connected = false;
	bool paired = false;
	bool resolved = false;
	bool has_service = false;

	if (strcmp(iface, DBUS_DEV_IFACE)) {
		return false;
	}
	sd_bus_message_enter_container(reply, 'a', "{sv}");
	while (sd_bus_message_enter_container(reply, 'e', "sv") > 0) {
		const char *propname;
		int boolval;
		ret = sd_bus_message_read(reply, "sv", &propname, "b", &boolval);
		if (ret >= 0) {
			if (!strcmp(propname, "Connected") && boolval)
				connected = true;
			if (!strcmp(propname, "Paired") && boolval)
				paired = true;
			if (!strcmp(propname, "ServicesResolved") && boolval)
				resolved = true;
		} else {
			sd_bus_message_rewind(reply, 0);
			ret = sd_bus_message_read_basic(reply, 's', &propname);
			if (ret >= 0 && !strcmp(propname, "Name") &&
			    name != NULL && sd_bus_message_read(reply, "v", "s", name) >= 0) {}
			if (ret >= 0 && !strcmp(propname, "UUIDs") &&
			   (sd_bus_message_enter_container(reply, SD_BUS_TYPE_VARIANT, "as") >= 0)) {
				if (sd_bus_message_enter_container(reply, 'a', "s") >= 0) {
					const char *uuid;
					while(sd_bus_message_read_basic(reply, 's', &uuid) > 0) {
						if (!strcasecmp(uuid, FIDO_SERVICE_UUID))
							has_service = true;
					}
					sd_bus_message_exit_container(reply); /* s */
				}
				sd_bus_message_exit_container(reply); /* as */
			} else {
				sd_bus_message_skip(reply,"v");
			}
		}
		sd_bus_message_exit_container(reply); /* sv */
	}
	sd_bus_message_exit_container(reply);  /* {sv} */
	return connected && resolved && has_service && paired;
}

static int
init_ble_fido_dev(fido_dev_info_t *di,
    const char *path, const char *name)
{
	memset(di, 0, sizeof(*di));
	if (asprintf(&di->path, "%s%s", FIDO_BLE_PREFIX, path) &&
		(di->manufacturer = strdup("BLE")) &&
		(di->product = strdup(name))) {
		di->io = (fido_dev_io_t) {
			fido_ble_open,
			fido_ble_close,
			fido_ble_read,
			fido_ble_write,
		};
		di->transport = (fido_dev_transport_t) {
			fido_ble_rx,
			fido_ble_tx,
		};

		return 0;
	}

	free(di->product);
	free(di->manufacturer);
	free(di->path);
	explicit_bzero(di, sizeof(*di));

	return -1;
}

static int
fido_ble_add_device(void *data, const char *path, sd_bus_message *reply)
{
	struct manifest_ctx *ctx = (struct manifest_ctx *) data;
	const char *iface;
	if (sd_bus_message_read_basic(reply, 's', &iface) > 0) {
		const char *name;
		if (ble_fido_is_useable_device(iface, reply, &name)) {
			if (*ctx->olen < ctx->ilen) {
				if (!init_ble_fido_dev(&ctx->devlist[*ctx->olen], path, name))
					(*ctx->olen)++;
			}
		}
		sd_bus_message_rewind(reply, 0);
		sd_bus_message_skip(reply, "sa{sv}");
	}

	return 0;
}

int
fido_ble_manifest(fido_dev_info_t *devlist, size_t ilen, size_t *olen)
{
	sd_bus *bus;
	sd_bus_message *reply;
	int ret;
	struct manifest_ctx ctx;

	*olen = 0;
	if (ilen == 0)
		return FIDO_OK;
	if (devlist == NULL)
		return FIDO_ERR_INVALID_ARGUMENT;

	ctx.devlist = devlist;
	ctx.olen = olen;
	ctx.ilen = ilen;
	if (0>sd_bus_default_system(&bus))
		return FIDO_ERR_INTERNAL;

	ctx.bus = bus;
	ret = sd_bus_call_method(bus, "org.bluez", "/", "org.freedesktop.DBus.ObjectManager",
	    "GetManagedObjects", NULL, &reply, "");
	if (ret <= 0) {
		sd_bus_unref(bus);
		return FIDO_ERR_INTERNAL;
	}

	sd_bus_message_rewind(reply, 1);
	/* search what is connected */
	iterate_over_all_objs(reply, fido_ble_add_device, &ctx);

	sd_bus_message_unref(reply);
	sd_bus_unref(bus);
	return FIDO_OK;
}
