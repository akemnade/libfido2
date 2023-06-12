#include <sys/types.h>

#include "fido.h"
#include "fido/param.h"
#import <Foundation/Foundation.h>
#import <CoreBluetooth/CoreBluetooth.h>

#define FIDO_SERVICE_UUID "0000fffd-0000-1000-8000-00805f9b34fb"
#define FIDO_STATUS_UUID  "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb"
#define FIDO_CONTROL_POINT_UUID "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb"
#define FIDO_CONTROL_POINT_LENGTH_UUID "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb"
#define FIDO_SERVICE_REVISION_UUID "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb"

@interface FIDODevice : NSObject
	- (instancetype) initWithDev:(NSString *)dev;
	- (int) write:(const unsigned char *)data len:(size_t)len;
	- (int) read:(unsigned char *)data len:(size_t)len ms:(int)ms;
	- (size_t) getCPSize;
@end

@interface FIDODevice() <CBCentralManagerDelegate,CBPeripheralDelegate>
{
	NSUUID *_dev;
	CBPeripheral *_cbp;
	bool _powered;
	int _err;
	size_t cpSize;
	CBCentralManager *_centralManager;
	CBUUID *_fidoStatusUUID;
	CBUUID *_fidoControlPointUUID;
	CBUUID *_fidoControlPointLengthUUID;
	CBUUID *_fidoServiceRevisionUUID;
	CBCharacteristic *_fidoStatusChar;
	CBCharacteristic *_fidoControlPointChar;
	CBCharacteristic *_fidoControlPointLengthChar;
	CBCharacteristic *_fidoServiceRevisionChar;
	dispatch_semaphore_t _sema;
	NSMutableArray<NSData*> *_recvList;
}
@end


@implementation FIDODevice
- (instancetype) initWithDev:(NSString *)dev
{
	self = [super init];
	dispatch_queue_t queue = dispatch_queue_create("fido-ble", DISPATCH_QUEUE_SERIAL);
	_sema = dispatch_semaphore_create(0);
	_powered = false;
	_centralManager = [[CBCentralManager alloc] initWithDelegate:self queue:queue options:nil];
	//sleep(2);
	dispatch_semaphore_wait(_sema, DISPATCH_TIME_FOREVER);
	cpSize = 0;
	_fidoStatusUUID = [CBUUID UUIDWithString:@FIDO_STATUS_UUID];
	_fidoControlPointUUID = [CBUUID UUIDWithString:@FIDO_CONTROL_POINT_UUID];
	_fidoControlPointLengthUUID = [CBUUID UUIDWithString:@FIDO_CONTROL_POINT_LENGTH_UUID];
	_fidoServiceRevisionUUID = [CBUUID UUIDWithString:@FIDO_SERVICE_REVISION_UUID];
	_dev = [[NSUUID alloc] initWithUUIDString:dev];
	_recvList = [[NSMutableArray alloc] init];
	NSArray<CBPeripheral *> *plist = [_centralManager retrievePeripheralsWithIdentifiers:@[ _dev]];
	if (!plist)
		return nil;

	_cbp = [plist firstObject];
	[_centralManager connectPeripheral:_cbp options:nil];
	dispatch_semaphore_wait(_sema, DISPATCH_TIME_FOREVER);
	if ((_fidoStatusChar == nil) ||
	    (_fidoControlPointChar == nil) ||
	    (_fidoControlPointLengthChar == nil) ||
	    (_fidoServiceRevisionChar == nil) ||
	    (cpSize == 0)) 
		return nil;
	
	return self;
}

- (int)read:(unsigned char *)data len:(size_t)len ms:(int)ms
{
	NSData *packet = nil;
	if ([_cbp state] != CBPeripheralStateConnected)
	       return FIDO_ERR_INTERNAL;

	dispatch_semaphore_wait(_sema, ms < 0 ? DISPATCH_TIME_FOREVER :
			dispatch_time(DISPATCH_TIME_NOW, 1000 * 1000));

	if ([_cbp state] != CBPeripheralStateConnected)
	       return FIDO_ERR_INTERNAL;

	@synchronized(_recvList) {
		if ([_recvList count] > 0) {
			packet = [_recvList firstObject];
			if (packet != nil) {
				if ([packet length] <len)
					len = [packet length];

				[packet getBytes:data length:(NSUInteger) len];
				[_recvList removeObjectAtIndex:0];
				return (int)len;
			}
		}
	}

	return FIDO_ERR_INTERNAL;
}

- (int)write:(const unsigned char *)data len:(size_t)len
{
	NSData *sendData = [NSData dataWithBytes:data length:len];
	if (_fidoControlPointChar == nil)
		return FIDO_ERR_INTERNAL;

	if ([_cbp state] != CBPeripheralStateConnected)
	       return FIDO_ERR_INTERNAL;

	[_cbp writeValue:sendData forCharacteristic:_fidoControlPointChar type:CBCharacteristicWriteWithResponse];
	dispatch_semaphore_wait(_sema, DISPATCH_TIME_FOREVER);
	return _err;
}

- (size_t)getCPSize
{
	return cpSize;
}

- (void)peripheral:(CBPeripheral *)peripheral didWriteValueForCharacteristic:(CBCharacteristic *)characteristic error:(NSError *)error
{
	if (error == nil) 
		_err = 0;
	else
		_err = FIDO_ERR_INTERNAL;

	dispatch_semaphore_signal(_sema);
}

- (void)peripheral:(CBPeripheral *)peripheral didUpdateValueForCharacteristic:(CBCharacteristic *)characteristic error:(NSError *)error
{
	if (peripheral != _cbp)
		return;

	if (characteristic == _fidoStatusChar) {
		NSData *val = [characteristic value];
		if (val != nil) {
			@synchronized(_recvList) {
				[_recvList addObject:[characteristic value]];
			}
			dispatch_semaphore_signal(_sema);
	
		}
	} else if (characteristic == _fidoControlPointLengthChar) {
		NSData *val = [characteristic value];
		if (val != nil) {
			uint8_t v[2];
			if ([val length] == 2)
				[val getBytes:v length:2];

			cpSize = ((size_t)v[0] << 8) + v[1];
		}
		dispatch_semaphore_signal(_sema);
	}
}

- (void)peripheral:(CBPeripheral *)peripheral didDiscoverCharacteristicsForService:(CBService *)service error:(NSError *)error
{
	NSArray<CBCharacteristic *> *characteristics = [service characteristics];
	CBCharacteristic *characteristic;

	if (![[service UUID] isEqual:[CBUUID UUIDWithString:@FIDO_SERVICE_UUID]])
		return;

	for(characteristic in characteristics) {
		if ([[characteristic UUID] isEqual:_fidoStatusUUID]) {
			_fidoStatusChar = characteristic;
			[peripheral setNotifyValue:YES forCharacteristic:characteristic];
		}

		if ([[characteristic UUID] isEqual:_fidoControlPointUUID])
			_fidoControlPointChar = characteristic;

		if ([[characteristic UUID] isEqual:_fidoControlPointLengthUUID])
			_fidoControlPointLengthChar = characteristic;

		if ([[characteristic UUID] isEqual:_fidoServiceRevisionUUID])
			_fidoServiceRevisionChar = characteristic;
	}

	if (_fidoControlPointLengthChar != nil)
		[_cbp readValueForCharacteristic:_fidoControlPointLengthChar];
	else
		dispatch_semaphore_signal(_sema);

}
- (void)peripheral:(CBPeripheral *)peripheral didDiscoverServices:(NSError *)error
{
	if (_cbp != peripheral)
		return;

	sleep(1);
	NSArray *services = [peripheral services];
	NSArray<CBUUID*> *chars = @[ _fidoStatusUUID,
				     _fidoControlPointUUID,
				     _fidoControlPointLengthUUID,
				     _fidoServiceRevisionUUID ];
	if (services != nil)
		for (CBService *service in services) {
			if (![[service UUID] isEqual:[CBUUID UUIDWithString:@FIDO_SERVICE_UUID]])
				continue;

			[peripheral discoverCharacteristics:chars forService:service];
			return;
		}

	dispatch_semaphore_signal(_sema);
}

- (void)centralManager:(CBCentralManager *)central didDisconnectPeripheral:(CBPeripheral *)peripheral
{
	dispatch_semaphore_signal(_sema);
}

- (void)centralManager:(CBCentralManager *)central didFailToConnectPeripheral:(CBPeripheral *)peripheral
{
	dispatch_semaphore_signal(_sema);
}

- (void)centralManager:(CBCentralManager *)central didConnectPeripheral:(CBPeripheral *)peripheral
{
	if (_cbp != peripheral)
		return;

	sleep(1);
	[_cbp setDelegate:self];
	[_cbp discoverServices:@[[CBUUID UUIDWithString:@FIDO_SERVICE_UUID]]];
}

- (void)centralManagerDidUpdateState:(CBCentralManager *)central
{
	if ([_centralManager state] == CBManagerStatePoweredOn) {
		if (!_powered) {
			_powered = true;
			dispatch_semaphore_signal(_sema);
		}
	}
}
@end

void *
fido_bluetooth_open(const char *path)
{
	if (!fido_is_bluetooth(path))
		return NULL;

	path += strlen(FIDO_BLUETOOTH_PREFIX);

	FIDODevice *dev = [[FIDODevice alloc] initWithDev:[NSString stringWithUTF8String: path]];

	return dev;
}

void fido_bluetooth_close(void *handle)
{
	(void)handle;
}

int
fido_bluetooth_read(void *handle, unsigned char *buf, size_t len, int ms)
{
	FIDODevice *dev = (FIDODevice *)handle;
	return [dev read:buf len:len ms:ms];
}

int
fido_bluetooth_write(void *handle, const unsigned char *buf, size_t len)
{
	FIDODevice *dev = (FIDODevice *)handle;
	int ret = [dev write:buf len:len];
	return ret;
}

size_t
fido_bluetooth_get_cp_size(fido_dev_t *d)
{
	FIDODevice *dev = (FIDODevice *)d->io_handle;
	return [dev getCPSize];
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

@interface FIDODiscover : NSObject
       - (instancetype) init;
       - (NSDictionary<NSString*,NSString*>*) search;
@end

@interface FIDODiscover() <CBCentralManagerDelegate>
{
	NSMutableDictionary<NSString*, NSString*> *results;
	CBCentralManager *_centralManager;
}
@end


@implementation FIDODiscover
- (instancetype) init
{
	self = [super init];
	results = [[NSMutableDictionary alloc] init];
	return self;
}

- (void)centralManagerDidUpdateState:(CBCentralManager *)central
{
	if ([_centralManager state] == CBManagerStatePoweredOn)
    		[_centralManager scanForPeripheralsWithServices:@[[CBUUID UUIDWithString:@FIDO_SERVICE_UUID]]
				options:@{CBCentralManagerScanOptionAllowDuplicatesKey: @NO}];
}

- (void) centralManager:(CBCentralManager *) central didDiscoverPeripheral:(CBPeripheral *)peripheral advertisementData:(NSDictionary *)advertisementData RSSI:(NSNumber *)RSSI
{
	[results setValue: [peripheral name] forKey:[[peripheral identifier] UUIDString]];
}

- (NSMutableDictionary<NSString*,NSString*>*) search
{
	{
		dispatch_queue_t queue = dispatch_queue_create("fido-ble", DISPATCH_QUEUE_SERIAL);
		_centralManager = [[CBCentralManager alloc] initWithDelegate:self queue: queue];
		sleep(3);
		[_centralManager stopScan];

	}
	return results;
}

@end

int
fido_bluetooth_manifest(fido_dev_info_t *devlist, size_t ilen, size_t *olen)
{
	NSDictionary<NSString*,NSString *> *results;
	NSString *uuid;
	*olen = 0;
	if (ilen == 0)
		return FIDO_OK;
	if (devlist == NULL)
		return FIDO_ERR_INVALID_ARGUMENT;

	FIDODiscover *fidodiscover = [[FIDODiscover alloc] init];
	results = [fidodiscover search];
	for (uuid in results) {
		init_ble_fido_dev(devlist, [uuid UTF8String], [[results valueForKey: uuid] UTF8String]);
		ilen--;
		(*olen)++;
		devlist++;
	}
	return FIDO_OK;
}
