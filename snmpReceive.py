from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.proto.api import v2c

# Create SNMP engine with autogenernated engineID and pre-bound
# to socket transport dispatcher
snmpEngine = engine.SnmpEngine()

# Transport setup

# UDP over IPv4
config.addTransport(
    snmpEngine,
    udp.domainName,
    udp.UdpTransport().openServerMode(('0.0.0.0', 162))
)

# SNMPv1/2c setup
config.addV1System(snmpEngine, 'my-area', 'public')

# SNMPv3/USM setup

# user: usr-md5-des, auth: MD5, priv DES
config.addV3User(
    snmpEngine, 'usr-md5-des',
    config.usmHMACMD5AuthProtocol, 'authkey1',
    config.usmDESPrivProtocol, 'privkey1'
)

# user: usr-md5-des, auth: MD5, priv DES, securityEngineId: 8000000001020304
# this USM entry is used for TRAP receiving purposes
config.addV3User(
    snmpEngine, 'usr-md5-des',
    config.usmHMACMD5AuthProtocol, 'authkey1',
    config.usmDESPrivProtocol, 'privkey1',
    securityEngineId=v2c.OctetString(hexValue='8000000001020304')
)

# user: usr-md5-none, auth: MD5, priv NONE
config.addV3User(
    snmpEngine, 'usr-md5-none',
    config.usmHMACMD5AuthProtocol, 'authkey1'
)

# user: usr-md5-none, auth: MD5, priv NONE, securityEngineId: 8000000001020304
# this USM entry is used for TRAP receiving purposes
config.addV3User(
    snmpEngine, 'usr-md5-none',
    config.usmHMACMD5AuthProtocol, 'authkey1',
    securityEngineId=v2c.OctetString(hexValue='8000000001020304')
)

# user: usr-sha-aes128, auth: SHA, priv AES
config.addV3User(
    snmpEngine, 'usr-sha-aes128',
    config.usmHMACSHAAuthProtocol, 'authkey1',
    config.usmAesCfb128Protocol, 'privkey1'
)

config.addV3User(
    snmpEngine, 'usr-sha-aes',
    config.usmHMAC192SHA256AuthProtocol, 'authkey1',
    config.usmAesCfb128Protocol, 'privkey1',
    # securityEngineId=v2c.OctetString(hexValue='8000000001020304')
)

# user: usr-sha-aes128, auth: SHA, priv AES, securityEngineId: 8000000001020304
# this USM entry is used for TRAP receiving purposes
config.addV3User(
    snmpEngine, 'usr-sha-aes128',
    config.usmHMACSHAAuthProtocol, 'authkey1',
    config.usmAesCfb128Protocol, 'privkey1',
    securityEngineId=v2c.OctetString(hexValue='8000000001020304')
)


# Callback function for receiving notifications
# noinspection PyUnusedLocal,PyUnusedLocal,PyUnusedLocal
def cbFun(snmpEngine, stateReference, contextEngineId, contextName,
          varBinds, cbCtx):
    print(snmpEngine,stateReference,contextEngineId,contextName,varBinds,cbCtx)
    print('Notification from ContextEngineId "%s", ContextName "%s"' % (
        contextEngineId.prettyPrint(), contextName.prettyPrint()))
    for name, val in varBinds:
        print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))


# Register SNMP Application at the SNMP engine
ntfrcv.NotificationReceiver(snmpEngine, cbFun)

snmpEngine.transportDispatcher.jobStarted(1)  # this job would never finish

# Run I/O dispatcher which would receive queries and send confirmations
try:
    snmpEngine.transportDispatcher.runDispatcher()
except:
    snmpEngine.transportDispatcher.closeDispatcher()
    raise
