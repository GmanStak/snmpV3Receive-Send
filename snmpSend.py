from pysnmp.hlapi import *


trap_oid = ObjectIdentity('1.3.6.1.6.3.1.1.5.2')  # SNMPv2-MIB::snmpTrapOID
var_binds = (
    (ObjectType(trap_oid, '1.3.6.1.6.3.1.1.5.1'), 'coldStart'),
    (ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'), 'example sysDescr')),
    (ObjectType(ObjectIdentity('1.3.6.1.2.1.1.3.0'), '12345')),
)
mib = {ObjectIdentifier('1.3.6.1.2.1.2.2.1.1.123'): 123,
       ObjectIdentifier('1.3.6.1.2.1.2.2.1.7.123'): 'testing',
       ObjectIdentifier('1.3.6.1.2.1.2.2.1.8.123'): 'up'}

errorIndication, errorStatus, errorIndex, varBinds = next(
    sendNotification(
        SnmpEngine(OctetString(hexValue='8000000001020304')),
        UsmUserData('usr-sha-aes128', 'authkey1', 'privkey1',
                    authProtocol=usmHMACSHAAuthProtocol,
                    privProtocol=usmAesCfb128Protocol),
        UdpTransportTarget(('snmp接收地址', 162)),
        ContextData(),
        'trap',
        # NotificationType(ObjectIdentity('SNMPv2-MIB', 'authenticationFailure'))
        NotificationType(trap_oid)
        # var_binds
    )
)

if errorIndication:
    print(errorIndication)
else:
    print("send success.")
