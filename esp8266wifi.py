"""
.. module:: esp8266wifi

*******************
ESP8266 Wifi Module
*******************

This module implements the Zerynth driver for the Espressif ESP8266 Wi-Fi chip (`Resources and Documentation <https://espressif.com/en/products/hardware/esp8266ex/resources>`_).

.. note:: To avail the Wi-Fi functionalities, the end user had to follow this steps:
    
            * inizialize the Espressif ESP8266 chip using the :func:`init()` of this driver
            * exploit the Wi-Fi features using the :ref:`Wi-Fi Module <stdlib_wifi>` of the Zerynth Standard Library

    """




@native_c("_espwifi_init",["csrc/wifi_ifc.c"],["VHAL_WIFI"],[])
def _hwinit():
    pass


def auto_init():
    init()

def init():
    """
.. function:: init()  
        
        initializes the Wi-Fi chip connected to the device.
        
        Once ended this operation without errors, the Wi-Fi chip is ready to work and it can be handled using the :ref:`Wi-Fi Module <stdlib_wifi>` of the Zerynth Standard Library.      
            
    """
    _hwinit()
    __builtins__.__default_net["wifi"] = __module__
    __builtins__.__default_net["sock"][0] = __module__ #AF_INET
    __builtins__.__default_net["ssl"] = __module__

@native_c("esp_wifi_link",[],[])
def link(ssid,sec,password):
    pass

@native_c("esp_wifi_is_linked",[],[])
def is_linked():
    pass


@native_c("esp_wifi_scan",["csrc/*"])
def scan(duration):
    pass

@native_c("esp_wifi_unlink",["csrc/*"])
def unlink():
    pass


@native_c("esp_wifi_link_info",[])
def link_info():
    pass

@native_c("esp_wifi_set_link_info",[])
def set_link_info(ip,mask,gw,dns):
    pass

@native_c("esp_wifi_resolve",["csrc/*"])
def gethostbyname(hostname):
    pass


@native_c("esp_wifi_socket",["csrc/*"])
def socket(family,type,proto):
    pass

# @native_c("esp_secure_socket",["csrc/*"])
# def secure_socket(family, type, proto):
#     pass

@native_c("esp_wifi_setsockopt",["csrc/*"])
def setsockopt(sock,level,optname,value):
    pass


@native_c("esp_wifi_close",["csrc/*"])
def close(sock):
    pass


@native_c("esp_wifi_sendto",["csrc/*"])
def sendto(sock,buf,addr,flags=0):
    pass

@native_c("esp_wifi_send",["csrc/*"])
def send(sock,buf,flags=0):
    pass

@native_c("esp_wifi_send_all",["csrc/*"])
def sendall(sock,buf,flags=0):
    pass


@native_c("esp_wifi_recv_into",["csrc/*"])
def recv_into(sock,buf,bufsize,flags=0,ofs=0):
    pass


@native_c("esp_wifi_recvfrom_into",["csrc/*"])
def recvfrom_into(sock,buf,bufsize,flags=0):
    pass


@native_c("esp_wifi_bind",["csrc/*"])
def bind(sock,addr):
    pass

@native_c("esp_wifi_listen",["csrc/*"])
def listen(sock,maxlog=2):
    pass

@native_c("esp_wifi_accept",["csrc/*"])
def accept(sock):
    pass

@native_c("esp_wifi_connect",["csrc/*"])
def connect(sock,addr):
    pass

@native_c("esp_wifi_select",[])
def select(rlist,wist,xlist,timeout):
    pass

# @native_c("bcm_set_antenna",[])
# def set_antenna(antenna):
#     """
# .. function:: set_antenna(antenna)

#     Select the antenna to be used:

#         * 0: antenna 0
#         * 1: antenna 1
#         * 3: automatic antenna selection

#     """
#     pass

@native_c("esp_softap_init",["csrc/*"])
def softap_init(ssid,sec,password,max_conn):
    pass

@native_c("esp_softap_config",["csrc/*"])
def softap_config(ip,gw,net):
    pass

@native_c("esp_turn_ap_off",["csrc/*"])
def softap_off():
    pass

@native_c("esp_turn_station_on",["csrc/*"])
def station_on():
    pass

@native_c("esp_turn_station_off",["csrc/*"])
def station_off():
    pass

@native_c("esp_softap_get_info",["csrc/*"])
def softap_get_info():
    pass

@native_c("esp_wifi_rssi",[])
def get_rssi():
    """
.. function:: get_rssi()

    Returns the current RSSI in dBm

    """
    pass

# @native_c("bcm_last_error",[])
# def get_error():
    # """
# .. function:: get_error()

#     Return the last connection error as an internal code.

#     """
#     pass

#####SPI
# @native_c("bcm_init",
#     ["csrc/ifc/wwd_ifc.c",
#     "csrc/ifc/bcm_host_rtos.c",
#     "csrc/ifc/bcm_host_platform.c",
#     "csrc/ifc/bcm_host_bus_spi.c",
#     "csrc/ifc/lwip/arch/*",
#     "csrc/WWD/internal/*",
#     "csrc/WWD/internal/bus_protocols/*",
#     "csrc/WWD/internal/bus_protocols/SPI/*",
#     "csrc/resources/*",
#     "csrc/platform/*",
#     "csrc/libraries/utilities/TLV/*",
#     "csrc/network/LwIP/WWD/*",
#     "csrc/WWD/internal/chips/43362A2/*",
#     "csrc/network/LwIP/ver/src/api/api_lib.c",
#     "csrc/network/LwIP/ver/src/api/api_msg.c",
#     "csrc/network/LwIP/ver/src/api/err.c",
#     "csrc/network/LwIP/ver/src/api/netbuf.c",
#     "csrc/network/LwIP/ver/src/api/netdb.c",
#     "csrc/network/LwIP/ver/src/api/netifapi.c",
#     "csrc/network/LwIP/ver/src/api/sockets.c",
#     "csrc/network/LwIP/ver/src/api/tcpip.c",
#     "csrc/network/LwIP/ver/src/core/dhcp.c",
#     "csrc/network/LwIP/ver/src/core/dns.c",
#     "csrc/network/LwIP/ver/src/core/init.c",
#     "csrc/network/LwIP/ver/src/core/ipv4/autoip.c",
#     "csrc/network/LwIP/ver/src/core/ipv4/icmp.c",
#     "csrc/network/LwIP/ver/src/core/ipv4/igmp.c",
#     "csrc/network/LwIP/ver/src/core/ipv4/inet.c",
#     "csrc/network/LwIP/ver/src/core/ipv4/inet_chksum.c",
#     "csrc/network/LwIP/ver/src/core/ipv4/ip.c",
#     "csrc/network/LwIP/ver/src/core/ipv4/ip_addr.c",
#     "csrc/network/LwIP/ver/src/core/ipv4/ip_frag.c",
#     "csrc/network/LwIP/ver/src/core/def.c",
#     "csrc/network/LwIP/ver/src/core/timers.c",
#     "csrc/network/LwIP/ver/src/core/mem.c",
#     "csrc/network/LwIP/ver/src/core/memp.c",
#     "csrc/network/LwIP/ver/src/core/netif.c",
#     "csrc/network/LwIP/ver/src/core/pbuf.c",
#     "csrc/network/LwIP/ver/src/core/raw.c",
#     "csrc/network/LwIP/ver/src/core/snmp/asn1_dec.c",
#     "csrc/network/LwIP/ver/src/core/snmp/asn1_enc.c",
#     "csrc/network/LwIP/ver/src/core/snmp/mib2.c",
#     "csrc/network/LwIP/ver/src/core/snmp/mib_structs.c",
#     "csrc/network/LwIP/ver/src/core/snmp/msg_in.c",
#     "csrc/network/LwIP/ver/src/core/snmp/msg_out.c",
#     "csrc/network/LwIP/ver/src/core/stats.c",
#     "csrc/network/LwIP/ver/src/core/sys.c",
#     "csrc/network/LwIP/ver/src/core/tcp.c",
#     "csrc/network/LwIP/ver/src/core/tcp_in.c",
#     "csrc/network/LwIP/ver/src/core/tcp_out.c",
#     "csrc/network/LwIP/ver/src/core/udp.c",
#     "csrc/network/LwIP/ver/src/netif/etharp.c",
#     #"csrc/BCM943362WCD4/*"
#     ],
#     ["VHAL_SPI",
#     'WICED_VERSION=\"3.3.1\"',
#     'BUS=\\\"SPI\\\"',
#     'BUS_IS_SPI',
#     'PLATFORM=\\\"BCM943362WCD4\\\"',
#     ],
#     [
#     "-I.../csrc/include",
#     "-I.../csrc/ifc",
#     "-I.../csrc/ifc/lwip",
#     "-I.../csrc/WWD/include",
#     "-I.../csrc/network/NoNS/WWD",
#     "-I.../csrc/WWD/internal/bus_protocols/SPI",
#     "-I.../csrc/WWD",
#     "-I.../csrc/WWD/internal/chips/43362A2",
#     "-I.../csrc/libraries/utilities/TLV",
#     "-I.../csrc/WWD/include/network",
#     "-I.../csrc",
#     "-I.../csrc/BCM943362WCD4",
#     "-I.../csrc/network/LwIP/WWD",
#     "-I.../csrc/network/LwIP/ver/src/include",
#     "-I.../csrc/network/LwIP/ver/src/include/ipv4",
#     ])
# def _hwinit(spi,nss,irq,boots0,boots1,wen,rst,country):
#    pass


