#define DRIVER_FUNC_INSTALL     0x01
#define DRIVER_FUNC_REMOVE      0x02

#define DRIVER_NAME       "wnbd"

BOOLEAN
ManageDriver(
    LPCTSTR  DriverName,
    LPCTSTR  ServiceName,
    USHORT   Function
);

BOOLEAN
SetupDriverName(
    PCHAR DriverLocation,
    ULONG BufferLength
);