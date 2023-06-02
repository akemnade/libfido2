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

static bool ble_fido_is_useable_device(const char *iface, sd_bus_message * reply, bool allow_unconnected, const char **name);
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

static void found_gatt_characteristic(struct ble *newdev, const char *path, sd_bus_message *reply)
{
	bool matches = false;
	bool status_found = false;
	bool control_point_found = false;
	bool control_point_length_found = false;
	bool service_revision_found = false;

	if (!newdev->paths.service) {
		sd_bus_message_skip(reply, "a{sv}");
		return;
	}
	if (sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "{sv}") < 0)
		return;

	while (0 < sd_bus_message_enter_container(reply, SD_BUS_TYPE_DICT_ENTRY, "sv")) {
		const char *prop;
		if (0 <= sd_bus_message_read_basic(reply, 's', &prop)) {
			if (!strcmp(prop, "Service")) {
				const char *devpath;
				if (0 <= sd_bus_message_read(reply, "v", "o", &devpath) &&
				    !strcmp(devpath, newdev->paths.service)) {
					matches = true;
				}
			} else if (!strcmp(prop, "UUID")) {
				const char *uuid;
				if (0 <= sd_bus_message_read(reply, "v", "s", &uuid)) {
					if (!strcmp(uuid, FIDO_STATUS_UUID))
						status_found = true;
					if (!strcmp(uuid, FIDO_CONTROL_POINT_UUID))
						control_point_found = true;
					if (!strcmp(uuid, FIDO_CONTROL_POINT_LENGTH_UUID))
						control_point_length_found = true;
					if (!strcmp(uuid, FIDO_SERVICE_REVISION_UUID))
						service_revision_found = true;
				}
			} else {
				sd_bus_message_skip(reply, "v");
			}
		}
		sd_bus_message_exit_container(reply);
	}
	sd_bus_message_exit_container(reply);
	if (!matches)
	       return;

	if (status_found)
		newdev->paths.status = strdup(path);

	if (control_point_found)
		newdev->paths.control_point = strdup(path);

	if (control_point_length_found)
		newdev->paths.control_point_length = strdup(path);

	if (service_revision_found)
		newdev->paths.service_revision = strdup(path);
}
static void found_gatt_service(struct ble *newdev, const char *path, sd_bus_message *reply)
{
	bool matches = false;
	bool service_found = false;
	if (sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "{sv}") < 0)
		return;

	while (0 < sd_bus_message_enter_container(reply, SD_BUS_TYPE_DICT_ENTRY, "sv")) {
		const char *prop;
		if (0 <= sd_bus_message_read_basic(reply, 's', &prop)) {
			if (!strcmp(prop, "Device")) {
				const char *devpath;
				if (0 <= sd_bus_message_read(reply, "v", "o", &devpath) &&
				    !strcmp(devpath, newdev->paths.dev)) {
					matches = true;
				}
			} else if (!strcmp(prop, "UUID")) {
				const char *uuid;
				if (0 <= sd_bus_message_read(reply, "v", "s", &uuid)) {
					if (!strcmp(uuid, FIDO_SERVICE_UUID))
						service_found = true;
				}
			} else {
				sd_bus_message_skip(reply, "v");
			}
		}
		sd_bus_message_exit_container(reply);
	}
	sd_bus_message_exit_container(reply);
	if (matches && service_found) {
		newdev->paths.service = strdup(path);
	}
}

static void collect_device_chars(void *data, const char *path, sd_bus_message *reply)
{
	struct ble *newdev = (struct ble *)data;
	const char *iface;
	if (sd_bus_message_read_basic(reply, 's', &iface) >= 0) {
		if (!strcmp(iface, DBUS_SERVICE_IFACE))
			found_gatt_service(newdev, path, reply);
		else if (!strcmp(iface, DBUS_CHAR_IFACE))
			found_gatt_characteristic(newdev, path, reply);
		else
			sd_bus_message_skip(reply, "a{sv}");
	}
}

static void iterate_over_all_objs(sd_bus_message *reply,
				  void (*new_dbus_interface)(void *,
				  const char *,
				  sd_bus_message *), void *data)
{
	if (sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "{oa{sa{sv}}}") <= 0)
		return;

	while (0 < sd_bus_message_enter_container(reply, SD_BUS_TYPE_DICT_ENTRY, "oa{sa{sv}}")) {
		const char *ifacepath = NULL;
		if (sd_bus_message_read_basic(reply, 'o', &ifacepath) <= 0)
			return;

		if (sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "{sa{sv}}") < 0)
			return;
		while (0 < sd_bus_message_enter_container(reply, SD_BUS_TYPE_DICT_ENTRY, "sa{sv}")) {
			new_dbus_interface(data, ifacepath, reply);
			sd_bus_message_exit_container(reply);
		}
		sd_bus_message_exit_container(reply);
		sd_bus_message_exit_container(reply);
	}
}

void *
fido_bluetooth_open(const char *path)
{
	struct ble *newdev;
	sd_bus_message *reply = NULL;
	int ret;
	if (!fido_is_bluetooth(path))
		return NULL;

	path += strlen(FIDO_BLUETOOTH_PREFIX);

	newdev = calloc(1, sizeof(*newdev));
	if (!newdev)
		return NULL;

	newdev->paths.dev = strdup(path);
	if (!newdev->paths.dev)
		goto out;

	if (0 > sd_bus_default_system(&newdev->bus))
		goto out;

	if (0 > sd_bus_call_method(newdev->bus, "org.bluez",
		path, "org.freedesktop.DBus.Properties", "GetAll", NULL, &reply,
		"s", DBUS_DEV_IFACE))
		goto out;

	if (!ble_fido_is_useable_device(DBUS_DEV_IFACE, reply, false, NULL))
		goto out;

	sd_bus_message_unref(reply);
	reply = NULL;
	ret = sd_bus_call_method(newdev->bus, "org.bluez", "/", "org.freedesktop.DBus.ObjectManager", "GetManagedObjects", NULL, &reply, "");
	if (ret <= 0)
		goto out;

	sd_bus_message_rewind(reply, 1);
	iterate_over_all_objs(reply, collect_device_chars, newdev);

	sd_bus_message_unref(reply);
	reply = NULL;

	if (newdev->paths.status &&
	    newdev->paths.control_point &&
	    newdev->paths.control_point_length &&
	    newdev->paths.service_revision) {
		uint8_t cp_len[2];
		uint8_t revision;
		if (0 > sd_bus_call_method(newdev->bus, "org.bluez", newdev->paths.control_point_length,
					DBUS_CHAR_IFACE, "ReadValue", NULL, &reply, "a{sv}", 0))
			goto out;

		if (0 > sd_bus_message_read(reply, "ay", 2, cp_len, cp_len + 1))
			goto out;

		sd_bus_message_unref(reply);
		reply = NULL;

		if (0 > sd_bus_call_method(newdev->bus, "org.bluez", newdev->paths.service_revision,
					DBUS_CHAR_IFACE, "ReadValue", NULL, &reply, "a{sv}", 0))
			goto out;
		if (0 > sd_bus_message_read(reply, "ay", 1, &revision))
			goto out;

		/* for simplicity, we allow now only FIDO2 */
		if (!(revision & 0x20))
			goto out;

		if (0 > sd_bus_call_method(newdev->bus, "org.bluez", newdev->paths.service_revision,
				DBUS_CHAR_IFACE, "WriteValue", NULL, NULL, "aya{sv}", 1, 0x20, 0))
			goto out;

		newdev->controlpoint_size = ((size_t)cp_len[0] << 8) + cp_len[1];
		if (0 > sd_bus_call_method(newdev->bus, "org.bluez", newdev->paths.status,
					DBUS_CHAR_IFACE, "AcquireNotify", NULL, &reply, "a{sv}", 0))
			goto out;

		sd_bus_message_rewind(reply, 1);
		if (0 > sd_bus_message_read_basic(reply, 'h', &newdev->status_fd))
			goto out;
		return newdev;
	}
out:
	if (reply)
		sd_bus_message_unref(reply);

	free(newdev->paths.service_revision);
	free(newdev->paths.control_point_length);
	free(newdev->paths.control_point);
	free(newdev->paths.service);
	free(newdev->paths.dev);

	if (newdev->bus)
		sd_bus_unref(newdev->bus);

	free(newdev);
	return NULL;
}

void fido_bluetooth_close(void *handle)
{
	struct ble *dev = (struct ble *)handle;
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
fido_bluetooth_read(void *handle, unsigned char *buf, size_t len, int ms)
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
fido_bluetooth_write(void *handle, const unsigned char *buf, size_t len)
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

	sd_bus_message_append(send_msg, "a{sv}", 0);
	if (r < 0)
		goto out;

	r = sd_bus_call(dev->bus, send_msg, 0, NULL, NULL);
out:
	sd_bus_message_unref(send_msg);

	return r;
}

size_t
fido_bluetooth_get_cp_size(fido_dev_t *d)
{
	return ((struct ble *)d->io_handle)->controlpoint_size;
}


static bool ble_fido_is_useable_device(const char *iface, sd_bus_message * reply, bool allow_unconnected, const char **name)
{
	int ret;
	bool connected = false;
	bool paired = false;
	bool resolved = false;
	bool has_service = false;

	if (strcmp(iface, DBUS_DEV_IFACE)) {
		return false;
	}
	sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "{sv}");
	while (0 < sd_bus_message_enter_container(reply, SD_BUS_TYPE_DICT_ENTRY, "sv")) {
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
				if (sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "s") >= 0) {
					const char *uuid;
					while(sd_bus_message_read_basic(reply, 's', &uuid)) {
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
	return (allow_unconnected || connected) && (allow_unconnected || resolved) && has_service && paired;
}

static int init_ble_fido_dev(fido_dev_info_t *di,
			      const char *path, const char *name)
{
	memset(di, 0, sizeof(*di));
	if (asprintf(&di->path, "%s%s", FIDO_BLUETOOTH_PREFIX, path) &&
		(di->manufacturer = strdup("BLE")) &&
		(di->product = strdup(name))) {
		di->io = (fido_dev_io_t) {
			fido_bluetooth_open,
			fido_bluetooth_close,
			fido_bluetooth_read,
			fido_bluetooth_write,
		};
		di->transport = (fido_dev_transport_t) {
			fido_bluetooth_rx,
			fido_bluetooth_tx,
		};

		return 0;
	}

	free(di->product);
	free(di->manufacturer);
	free(di->path);
	explicit_bzero(di, sizeof(*di));

	return -1;
}

static void fido_bluetooth_add_device(void *data, const char *path, sd_bus_message *reply)
{
	struct manifest_ctx *ctx = (struct manifest_ctx *) data;
	const char *iface;
	if (sd_bus_message_read_basic(reply, 's', &iface) > 0) {
		const char *name;
		if (ble_fido_is_useable_device(iface, reply, false, &name)) {
			if (!init_ble_fido_dev(&ctx->devlist[*ctx->olen], path, name)) {
				if (++(*ctx->olen) == ctx->ilen)
					return;
			}
		}
		sd_bus_message_rewind(reply, 0);
		sd_bus_message_skip(reply, "sa{sv}");
	}
}

int
fido_bluetooth_manifest(fido_dev_info_t *devlist, size_t ilen, size_t *olen)
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
	iterate_over_all_objs(reply, fido_bluetooth_add_device, &ctx);

	sd_bus_message_unref(reply);
	sd_bus_unref(bus);
	return FIDO_OK;
}
