#include <sys/types.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-bus-vtable.h>

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

static sd_bus_slot *profile_slot = NULL;
static sd_bus_slot *profile_manager_slot = NULL;
static bool ble_fido_is_useable_device(const char *iface, sd_bus_message * reply, bool allow_unconnected, const char **name);
struct ble {
	sd_bus *bus;
	sd_bus_slot *slot;
	struct {
		char *dev;
		char *service;
		char *status;
		char *control_point;
		char *control_point_length;
		char *service_revision;
	} paths;
	size_t controlpoint_size;
	uint8_t *reply_buf;
	size_t reply_len;
};

struct manifest_ctx {
	sd_bus *bus;
	fido_dev_info_t *devlist;
	size_t ilen;
	size_t *olen;
	bool scanning;
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

static int registered_application(sd_bus_message *reply, void *user_data, sd_bus_error *ret_error)
{
	(void)reply;
	(void)ret_error;
	*(bool *)user_data = true;
	return 0;
}

static void disable_ble_adapters(void *data, const char *path, sd_bus_message *reply)
{
	const char *iface;
	sd_bus *bus = (sd_bus *) data;
	if (sd_bus_message_read_basic(reply, 's', &iface) >= 0) {
		if (!strcmp(iface, DBUS_GATTMANAGER_IFACE)) {
			bool finished = false;
			int ret;
			sd_bus_call_method_async(bus, NULL, "org.bluez", path, iface, "UnregisterApplication",
						 registered_application, &finished, "o", "/org/fido");
			while (!finished) {
				ret = sd_bus_process(bus, NULL);
				if (ret < 0)
					return;

				if (ret == 0) {
					ret = sd_bus_wait(bus, UINT64_MAX);
					if (ret <= 0)
						return;
				}
			}
		}
		sd_bus_message_skip(reply, "a{sv}");
	}
}

static void enable_ble_adapters(void *data, const char *path, sd_bus_message *reply)
{
	const char *iface;
	struct manifest_ctx *ctx = (struct manifest_ctx *) data;
	if (sd_bus_message_read_basic(reply, 's', &iface) >= 0) {
		if (!strcmp(iface, DBUS_ADAPTER_IFACE)) {
			/* will also fail if adapter is not powered */
			if (sd_bus_call_method(ctx->bus, "org.bluez", path, iface,
					       "StartDiscovery", NULL, NULL, "") >= 0) {
				ctx->scanning = true;
			}
		} else if (!strcmp(iface, DBUS_GATTMANAGER_IFACE)) {
			bool finished = false;
			int ret;
			sd_bus_call_method_async(ctx->bus, NULL, "org.bluez", path, iface, "RegisterApplication",
						 registered_application, &finished, "oa{sv}", "/org/fido", 0);
			/* we need to do it async to enable introspection of our profile */
			while (!finished) {
				ret = sd_bus_process(ctx->bus, NULL);
				if (ret < 0)
					return;

				if (ret == 0) {
					ret = sd_bus_wait(ctx->bus, UINT64_MAX);
					if (ret <= 0)
						return;
				}
			}
		}
		sd_bus_message_skip(reply, "a{sv}");
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

static int read_cb(sd_bus_message *m, void *userdata,
		sd_bus_error *ret_error)
{
	struct ble *dev = (struct ble *)userdata;
	const char *iface;

	(void)ret_error;
	sd_bus_message_rewind(m, 1);
	if (sd_bus_message_read_basic(m, 's', &iface) < 0)
		return 0;

	if (strcmp(iface, DBUS_CHAR_IFACE))
		return 0;

	if (sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "{sv}") < 0)
		return 0;

	while (0 < sd_bus_message_enter_container(m, SD_BUS_TYPE_DICT_ENTRY, "sv")) {
		const char *prop;
		if (sd_bus_message_read_basic(m, 's', &prop) < 0) {
			return 0;
		}

		if (!strcmp(prop, "Value")) {
			uint8_t *value;
			size_t value_len;
			if (sd_bus_message_enter_container(m, SD_BUS_TYPE_VARIANT, "ay") < 0)
				return 0;

			if (sd_bus_message_read_array(m, 'y', (void *)&value, &value_len) <= 0)
				return 0;

			if (value_len > dev->controlpoint_size)
				value_len = dev->controlpoint_size;

			memcpy(dev->reply_buf, value, value_len);
			dev->reply_len = value_len;

			return 1;
		} else {
			sd_bus_message_skip(m, "v");
		}

		sd_bus_message_exit_container(m);
	}
	return 0;
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
	sd_bus_message *reply;
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

		newdev->controlpoint_size = ((size_t)cp_len[0] << 8) + cp_len[1];
		newdev->reply_buf = calloc(1, newdev->controlpoint_size);

		if (0 > sd_bus_call_method(newdev->bus, "org.bluez", newdev->paths.status,
					DBUS_CHAR_IFACE, "StartNotify", NULL, NULL, ""))
			goto out;

		if (0 > sd_bus_match_signal(newdev->bus, &newdev->slot, "org.bluez",
					newdev->paths.status,
					"org.freedesktop.DBus.Properties", "PropertiesChanged",
					read_cb, newdev))
			goto out;

		return newdev;
	}
out:
	if (reply)
		sd_bus_message_unref(reply);

	if (newdev->reply_buf)
		explicit_bzero(newdev->reply_buf, newdev->controlpoint_size);
	free(newdev->reply_buf);
	free(newdev->paths.service_revision);
	free(newdev->paths.control_point_length);
	free(newdev->paths.control_point);
	free(newdev->paths.service);
	free(newdev->paths.dev);
	if (newdev->slot)
		sd_bus_slot_unref(newdev->slot);

	if (newdev->bus)
		sd_bus_unref(newdev->bus);

	free(newdev);
	return NULL;
}

void fido_bluetooth_close(void *handle)
{
	struct ble *dev = (struct ble *)handle;
	sd_bus_call_method(dev->bus, "org.bluez", dev->paths.status,
			   DBUS_CHAR_IFACE, "StopNotify", NULL, NULL, "");
	if (dev->reply_buf)
		explicit_bzero(dev->reply_buf, dev->controlpoint_size);
	free(dev->reply_buf);
	free(dev->paths.service_revision);
	free(dev->paths.control_point_length);
	free(dev->paths.control_point);
	free(dev->paths.service);
	free(dev->paths.dev);
	if (dev->slot)
		sd_bus_slot_unref(dev->slot);

	if (dev->bus)
		sd_bus_unref(dev->bus);

	free(dev);
}

int
fido_bluetooth_read(void *handle, unsigned char *buf, size_t len, int ms)
{
	struct ble *dev = (struct ble *)handle;
	dev->reply_len = 0;
	while(dev->reply_len == 0) {
		int ret = sd_bus_process(dev->bus, NULL);
		if (ret < 0)
			return FIDO_ERR_INTERNAL;

		if (ret == 0) {
			ret = sd_bus_wait(dev->bus, ms < 0 ? UINT64_MAX : (uint64_t)ms * 1000);
			if (ret == 0) /* timeout */
				return -1;

			if (ret < 0)
				return FIDO_ERR_INTERNAL;
		} else if (dev->reply_len > 0) {
			if (dev->reply_len < len)
				len = dev->reply_len;

			dev->reply_len = 0;
			memcpy(buf, dev->reply_buf, len);
			return (int)len;
		}
	}

	return FIDO_ERR_INTERNAL;
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
		return -1;

	r = sd_bus_message_append_array(send_msg, 'y', buf, len);
	if (r < 0)
		return -1;

	sd_bus_message_append(send_msg, "a{sv}", 0);
	if (r < 0)
		return -1;

	dev->reply_len = 0;
	r = sd_bus_call(dev->bus, send_msg, 0, NULL,NULL);
	if (r < 0)
		return -1;

	return 0;
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
	while (0 < (ret = sd_bus_message_enter_container(reply, SD_BUS_TYPE_DICT_ENTRY, "sv"))) {
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

static int release_profile_cb(sd_bus_message *m, void *userdata, sd_bus_error *error) {
	(void)m;
	(void)userdata;
	(void)error;
	return 0;
}

static int get_fido_uuid(sd_bus *bus, const char *path, const char *interface, const char *property,
                                            sd_bus_message *reply, void *userdata, sd_bus_error *ret_error)
{
	(void) bus;
	(void) path;
	(void) interface;
	(void) property;
	(void) userdata;
	(void) ret_error;

	return sd_bus_message_append(reply, "as",1 ,FIDO_SERVICE_UUID);
}

static void add_profile(sd_bus *bus)
{
	static const sd_bus_vtable vtable[] = {
		SD_BUS_VTABLE_START(0),
		SD_BUS_METHOD("Release", NULL, NULL, release_profile_cb, 0),
		SD_BUS_PROPERTY("UUIDs", "as", get_fido_uuid, 0,
				SD_BUS_VTABLE_PROPERTY_CONST),
		SD_BUS_VTABLE_END,
	};

	if (!profile_manager_slot)
		sd_bus_add_object_manager(bus, &profile_manager_slot, "/org/fido");
	if (!profile_slot)
		sd_bus_add_object_vtable(bus, &profile_slot, "/org/fido/bleprofile",
					 DBUS_PROFILE_IFACE, vtable, NULL);
}

static void remove_profile()
{
	if (profile_manager_slot) {
		sd_bus_slot_unref(profile_manager_slot);
		profile_manager_slot = NULL;
	}

	if (profile_slot) {
		sd_bus_slot_unref(profile_slot);
		profile_slot = NULL;
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
	ctx.scanning = false;
	add_profile(bus);
	ret = sd_bus_call_method(bus, "org.bluez", "/", "org.freedesktop.DBus.ObjectManager",
				 "GetManagedObjects", NULL, &reply, "");
	if (ret <= 0)
		return FIDO_ERR_INTERNAL;

	sd_bus_message_rewind(reply, 1);
	/* register profile to let BLE fido devices connect */
	iterate_over_all_objs(reply, enable_ble_adapters, &ctx);
	/* if we are scanning, wait for something to be found */
	if (ctx.scanning)
		sleep(3);

	sd_bus_message_rewind(reply, 1);
	/* search what is connected */
	iterate_over_all_objs(reply, fido_bluetooth_add_device, &ctx);
	sd_bus_message_rewind(reply, 1);
	iterate_over_all_objs(reply, disable_ble_adapters, bus);
	remove_profile(bus);

	sd_bus_message_unref(reply);
	return FIDO_OK;
}
