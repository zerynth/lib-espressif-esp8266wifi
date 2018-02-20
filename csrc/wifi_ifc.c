#include "zerynth.h"
#include "esp8266/esp8266.h"
#include "esp8266/esp8266wifi.h"
#include "lwip/netif.h"
#include "lwip/dns.h"
#include "lwip/sockets.h"


extern void *g_ic;

#define DEFAULT_NETIF() ((struct netif*)(((uint8_t*)g_ic)+16))

int wifi_station_start(void);
int wifi_station_stop(void);
int wifi_mode_set(uint8_t mode);


uint8_t esp_has_link_info=0;
ip_addr_t esp_net_ip;
ip_addr_t esp_net_mask;
ip_addr_t esp_net_gw;
ip_addr_t esp_net_dns;


//#define printf(...) vbl_printf_stdout(__VA_ARGS__)
#define printf(...)

C_NATIVE(_espwifi_init) {
  NATIVE_UNWARN();
  int err;


  err = wifi_mode_set(STATIONAP_MODE);
  if(!err)
    return ERR_IOERROR_EXC;
  err = wifi_station_start();
  if(!err)
    return ERR_IOERROR_EXC;

  netif_set_default(DEFAULT_NETIF());

  err = wifi_set_opmode_current(STATION_MODE);  

  *res = MAKE_NONE();


  return ERR_OK;
}


C_NATIVE(esp_wifi_link) {
  NATIVE_UNWARN();


  uint8_t *ssid;
  int sidlen, sec, passlen;
  uint8_t *password;
  int32_t err;

  *res = MAKE_NONE();

  if (parse_py_args("sis", nargs, args, &ssid, &sidlen, &sec, &password, &passlen) != 3)
    return ERR_TYPE_EXC;

  err = wifi_set_opmode_current(STATION_MODE);
  if(!err)
    return ERR_IOERROR_EXC;

  struct station_config scfg;

  __memcpy(scfg.ssid, ssid, sidlen);
  __memcpy(scfg.password, password, passlen);
  scfg.ssid[sidlen]=0;
  scfg.password[passlen]=0;

  err = wifi_station_set_config_current(&scfg);
  if(!err)
    return ERR_IOERROR_EXC;


  RELEASE_GIL();
  wifi_station_dhcpc_stop();
  if (esp_has_link_info) {
    struct ip_info info;
    info.ip.addr = esp_net_ip.addr;
    info.gw.addr = esp_net_gw.addr;
    info.netmask.addr = esp_net_mask.addr;
    wifi_set_ip_info(STATION_IF,&info);
  } else {
   wifi_station_dhcpc_start();
  }
  err = wifi_station_connect();
  if(!err){
    ACQUIRE_GIL();
    return ERR_IOERROR_EXC;
  }


  STATION_STATUS ss;

  err=0;
  while ((ss = wifi_station_get_connect_status()) <= STATION_CONNECTING) {
    vosThSleep(TIME_U(1000, MILLIS));
    err++;
    if (err>30){
      ACQUIRE_GIL();
      return ERR_IOERROR_EXC;
    }
  }
  wifi_station_set_reconnect_policy(1);
  ACQUIRE_GIL();

  if(ss!=STATION_GOT_IP)
    return ERR_IOERROR_EXC;

  if(esp_has_link_info){
    dns_setserver(0, &esp_net_dns);
  }


/*
  esp_net_ip.addr = DEFAULT_NETIF()->ip_addr.addr;
  printf("%x %x %x\n",DEFAULT_NETIF()->ip_addr.addr,&(DEFAULT_NETIF()->ip_addr.addr),DEFAULT_NETIF());
  esp_net_gw.addr = DEFAULT_NETIF()->gw.addr;
  esp_net_mask.addr = DEFAULT_NETIF()->netmask.addr;
  esp_net_dns = dns_getserver(0);
*/

  return ERR_OK;
}

C_NATIVE(esp_wifi_unlink) {
  NATIVE_UNWARN();
  *res = MAKE_NONE();
  int err;

  RELEASE_GIL();
  err = wifi_station_disconnect();
  if (!err){
    ACQUIRE_GIL();
    return ERR_IOERROR_EXC;
  }

  STATION_STATUS ss;

  while ((ss = wifi_station_get_connect_status()) > STATION_IDLE) {
    vosThSleep(TIME_U(1000, MILLIS));
  }

  wifi_station_set_reconnect_policy(0);
  ACQUIRE_GIL();

  return ERR_OK;
}


C_NATIVE(esp_wifi_is_linked) {
  NATIVE_UNWARN();
  int err = wifi_station_get_connect_status();
  if(err!=STATION_GOT_IP) {
    *res = PBOOL_FALSE();
  } else {
    *res = PBOOL_TRUE();
  }
  return ERR_OK;
}


C_NATIVE(esp_wifi_link_info) {
  NATIVE_UNWARN();

  struct ip_info info;
  NetAddress addr;
  addr.port = 0;
  
  PTuple *tpl = psequence_new(PTUPLE, 5);

  wifi_get_ip_info(STATION_IF, &info);
  addr.ip = info.ip.addr;
  PTUPLE_SET_ITEM(tpl, 0, netaddress_to_object(&addr));
  addr.ip = info.netmask.addr;
  PTUPLE_SET_ITEM(tpl, 1, netaddress_to_object(&addr));
  addr.ip = info.gw.addr;
  PTUPLE_SET_ITEM(tpl, 2, netaddress_to_object(&addr));
  addr.ip = dns_getserver(0).addr;//esp_net_dns.addr;
  PTUPLE_SET_ITEM(tpl, 3, netaddress_to_object(&addr));

  PObject *mac = psequence_new(PBYTES, 6);
  wifi_get_macaddr(STATION_IF, PSEQUENCE_BYTES(mac));
  PTUPLE_SET_ITEM(tpl, 4, mac);
  *res = tpl;

  return ERR_OK;
}

C_NATIVE(esp_wifi_rssi) {
  NATIVE_UNWARN();
  int32_t rssi;

  rssi = wifi_station_get_rssi();
  if (rssi>=31)
     return ERR_IOERROR_EXC;
  *res = PSMALLINT_NEW(rssi);
  return ERR_OK;
}


C_NATIVE(esp_wifi_set_link_info) {
  C_NATIVE_UNWARN();

  NetAddress ip;
  NetAddress mask;
  NetAddress gw;
  NetAddress dns;

  if (parse_py_args("nnnn", nargs, args,
                    &ip,
                    &mask,
                    &gw,
                    &dns) != 4) return ERR_TYPE_EXC;

  if (dns.ip == 0) {
    OAL_MAKE_IP(dns.ip, 8, 8, 8, 8);
  }
  if (mask.ip == 0) {
    OAL_MAKE_IP(mask.ip, 255, 255, 255, 255);
  }
  if (gw.ip == 0) {
    OAL_MAKE_IP(gw.ip, OAL_IP_AT(ip.ip, 0), OAL_IP_AT(ip.ip, 1), OAL_IP_AT(ip.ip, 2), 1);
  }

  esp_net_ip.addr = ip.ip;
  esp_net_gw.addr = gw.ip;
  esp_net_dns.addr = dns.ip;
  esp_net_mask.addr = mask.ip;
  if (ip.ip != 0)
    esp_has_link_info = 1;
  else
    esp_has_link_info = 0;
 
  *res = MAKE_NONE();
  return ERR_OK;
}


C_NATIVE(esp_wifi_resolve) {
  C_NATIVE_UNWARN();
  uint8_t *url;
  uint32_t len;
  int32_t code;
  NetAddress addr;
  if (parse_py_args("s", nargs, args, &url, &len) != 1)
    return ERR_TYPE_EXC;
  addr.ip = 0;
  RELEASE_GIL();
  struct ip_addr ares;
  uint8_t *name = (uint8_t*)gc_malloc(len + 1);
  __memcpy(name, url, len);
  name[len] = 0;
  code = netconn_gethostbyname(name, &ares);
  gc_free(name);
  ACQUIRE_GIL();
  if (code != ERR_OK)
    return ERR_IOERROR_EXC;
  addr.port = 0;
  addr.ip = ares.addr;
  *res = netaddress_to_object(&addr);
  return ERR_OK;

}


#define DRV_SOCK_DGRAM 1
#define DRV_SOCK_STREAM 0
#define DRV_AF_INET 0

typedef struct sockaddr_in sockaddr_t;

void bcm_prepare_addr(sockaddr_t *vmSocketAddr, NetAddress *addr) {
  vmSocketAddr->sin_family = AF_INET;
  vmSocketAddr->sin_port = addr->port;
  vmSocketAddr->sin_addr.s_addr = addr->ip;
}
int errno;



C_NATIVE(esp_wifi_socket) {
  C_NATIVE_UNWARN();
  int32_t family;
  int32_t type;
  int32_t proto;
  if (parse_py_args("III", nargs, args, DRV_AF_INET, &family, DRV_SOCK_STREAM, &type, IPPROTO_TCP, &proto) != 3)
    return ERR_TYPE_EXC;
  if (type != DRV_SOCK_DGRAM && type != DRV_SOCK_STREAM)
    return ERR_TYPE_EXC;
  if (family != DRV_AF_INET)
    return ERR_UNSUPPORTED_EXC;
  RELEASE_GIL();
  int32_t sock = lwip_socket(AF_INET, (type == DRV_SOCK_DGRAM) ? SOCK_DGRAM : SOCK_STREAM,
                             (type == DRV_SOCK_DGRAM) ? IPPROTO_UDP : IPPROTO_TCP);
  ACQUIRE_GIL();
  printf("CMD_SOCKET: %i %i\n", sock, errno);
  if (sock < 0)
    return ERR_IOERROR_EXC;
  *res = PSMALLINT_NEW(sock);
  return ERR_OK;
}


C_NATIVE(esp_wifi_connect) {
  C_NATIVE_UNWARN();
  int32_t sock;
  NetAddress addr;

  if (parse_py_args("in", nargs, args, &sock, &addr) != 2)
    return ERR_TYPE_EXC;
  sockaddr_t vmSocketAddr;
  bcm_prepare_addr(&vmSocketAddr, &addr);
  RELEASE_GIL();
  sock = lwip_connect(sock, &vmSocketAddr, sizeof(vmSocketAddr));
  ACQUIRE_GIL();
  printf("CMD_OPEN: %i %i\r\n", sock, errno);
  if (sock < 0) {
    return ERR_IOERROR_EXC;
  }
  *res = PSMALLINT_NEW(sock);
  return ERR_OK;
}


C_NATIVE(esp_wifi_close) {
  C_NATIVE_UNWARN();
  int32_t sock;
  int rr;
  if (parse_py_args("i", nargs, args, &sock) != 1)
    return ERR_TYPE_EXC;
  RELEASE_GIL();
  rr = lwip_close(sock);
  printf("closing sock - result %i\n",rr);
  ACQUIRE_GIL();
  *res = PSMALLINT_NEW(sock);
  return ERR_OK;
}

C_NATIVE(esp_wifi_send) {
  C_NATIVE_UNWARN();
  uint8_t *buf;
  int32_t len;
  int32_t flags;
  int32_t sock;
  if (parse_py_args("isi", nargs, args,
                    &sock,
                    &buf, &len,
                    &flags) != 3) return ERR_TYPE_EXC;
  RELEASE_GIL();
  sock = lwip_send(sock, buf, len, flags);
  ACQUIRE_GIL();
  if (sock < 0) {
    return ERR_IOERROR_EXC;
  }
  *res = PSMALLINT_NEW(sock);
  return ERR_OK;
}

C_NATIVE(esp_wifi_send_all) {
  C_NATIVE_UNWARN();
  uint8_t *buf;
  int32_t len;
  int32_t flags;
  int32_t sock;
  int32_t wrt;
  int32_t w;
  if (parse_py_args("isi", nargs, args,
                    &sock,
                    &buf, &len,
                    &flags) != 3) return ERR_TYPE_EXC;
  RELEASE_GIL();
  wrt = 0;
  while (wrt < len) {
    w = lwip_send(sock, buf + wrt, len - wrt, flags);
    if (w < 0)
      break;
    wrt += w;
  }
  ACQUIRE_GIL();
  if (w < 0) {
    return ERR_IOERROR_EXC;
  }
  *res = MAKE_NONE();
  return ERR_OK;
}


C_NATIVE(esp_wifi_sendto) {
  C_NATIVE_UNWARN();
  uint8_t *buf;
  int32_t len;
  int32_t flags;
  int32_t sock;
  NetAddress addr;
  if (parse_py_args("isni", nargs, args,
                    &sock,
                    &buf, &len,
                    &addr,
                    &flags) != 4) return ERR_TYPE_EXC;

  RELEASE_GIL();
  sockaddr_t vmSocketAddr;
  bcm_prepare_addr(&vmSocketAddr, &addr);
  sock = lwip_sendto(sock, buf, len, flags, &vmSocketAddr, sizeof(sockaddr_t));
  ACQUIRE_GIL();

  if (sock < 0) {
    return ERR_IOERROR_EXC;
  }
  *res = PSMALLINT_NEW(sock);
  return ERR_OK;
}


C_NATIVE(esp_wifi_recv_into) {
  C_NATIVE_UNWARN();
  uint8_t *buf;
  int32_t len;
  int32_t sz;
  int32_t flags;
  int32_t ofs;
  int32_t sock;
  //printf("sock %i, buf %s, len %i, sz %i, flag %i, ofs %i\n",args[0],args[1],args[2],args[3],args[4],args[5]);
  if (parse_py_args("isiiI", nargs, args,
                    &sock,
                    &buf, &len,
                    &sz,
                    &flags,
                    0,
                    &ofs
                   ) != 5) return ERR_TYPE_EXC;
  buf += ofs;
  len -= ofs;
  len = (sz < len) ? sz : len;
  RELEASE_GIL();
  int rb = 0;
  int r;
  //printf("sock %i, buf %s, len %i, sz %i, flag %i, ofs %i\n",sock,buf,len,sz,flags,ofs);
  while (rb < len) {
    r = lwip_recv(sock, buf + rb, len - rb, flags);
    if (r <= 0)
      break;
    rb += r;
  }
  ACQUIRE_GIL();
  if (r < 0) {
    if (r == ETIMEDOUT)
      return ERR_TIMEOUT_EXC;
    return ERR_IOERROR_EXC;
  }
  *res = PSMALLINT_NEW(rb);

  return ERR_OK;
}



C_NATIVE(esp_wifi_recvfrom_into) {
  C_NATIVE_UNWARN();
  uint8_t *buf;
  int32_t len;
  int32_t sz;
  int32_t flags;
  int32_t ofs;
  int32_t sock;
  NetAddress addr;
  if (parse_py_args("isiiI", nargs, args,
                    &sock,
                    &buf, &len,
                    &sz,
                    &flags,
                    0,
                    &ofs
                   ) != 5) return ERR_TYPE_EXC;
  buf += ofs;
  len -= ofs;
  len = (sz < len) ? sz : len;

  RELEASE_GIL();
  addr.ip = 0;
  int r;
  sockaddr_t vmSocketAddr;
  socklen_t tlen = sizeof(vmSocketAddr);
  r = lwip_recvfrom(sock, buf, len, flags, &vmSocketAddr, &tlen);
  ACQUIRE_GIL();
  addr.ip = vmSocketAddr.sin_addr.s_addr;
  addr.port = vmSocketAddr.sin_port;
  if (r < 0) {
    if (r == ETIMEDOUT)
      return ERR_TIMEOUT_EXC;
    return ERR_IOERROR_EXC;
  }
  PTuple *tpl = (PTuple *) psequence_new(PTUPLE, 2);
  PTUPLE_SET_ITEM(tpl, 0, PSMALLINT_NEW(r));
  PObject *ipo = netaddress_to_object(&addr);
  PTUPLE_SET_ITEM(tpl, 1, ipo);
  *res = tpl;
  return ERR_OK;
}


C_NATIVE(esp_wifi_setsockopt) {
  C_NATIVE_UNWARN();
  int32_t sock;
  int32_t level;
  int32_t optname;
  int32_t optvalue;

  if (parse_py_args("iiii", nargs, args, &sock, &level, &optname, &optvalue) != 4)
    return ERR_TYPE_EXC;

  if (level==0xffff)
    level=SOL_SOCKET;

  // SO_RCVTIMEO zerynth value
  if (optname == 1) {
      optname = SO_RCVTIMEO;
  }

  RELEASE_GIL();
  sock = lwip_setsockopt(sock, level, optname, &optvalue, sizeof(optvalue));
  ACQUIRE_GIL();
  if (sock < 0)
    return ERR_IOERROR_EXC;

  *res = MAKE_NONE();
  return ERR_OK;
}

C_NATIVE(esp_wifi_bind) {
  C_NATIVE_UNWARN();
  int32_t sock;
  NetAddress addr;
  if (parse_py_args("in", nargs, args, &sock, &addr) != 2)
    return ERR_TYPE_EXC;
  sockaddr_t serverSocketAddr;
  //addr.ip = bcm_net_ip.addr;
  bcm_prepare_addr(&serverSocketAddr, &addr);
  RELEASE_GIL();
  sock = lwip_bind(sock, &serverSocketAddr, sizeof(sockaddr_t));
  ACQUIRE_GIL();
  printf("binding: %i\r\n", sock);
  if (sock < 0)
    return ERR_IOERROR_EXC;
  *res = MAKE_NONE();
  return ERR_OK;
}

C_NATIVE(esp_wifi_listen) {
  C_NATIVE_UNWARN();
  int32_t maxlog;
  int32_t sock;
  if (parse_py_args("ii", nargs, args, &sock, &maxlog) != 2)
    return ERR_TYPE_EXC;
  RELEASE_GIL();
  maxlog = lwip_listen(sock, maxlog);
  ACQUIRE_GIL();
  if (maxlog)
    return ERR_IOERROR_EXC;
  *res = MAKE_NONE();
  return ERR_OK;
}

C_NATIVE(esp_wifi_accept) {
  C_NATIVE_UNWARN();
  int32_t sock;
  NetAddress addr;
  if (parse_py_args("i", nargs, args, &sock) != 1)
    return ERR_TYPE_EXC;
  sockaddr_t clientaddr;
  socklen_t addrlen;
  memset(&clientaddr, 0, sizeof(sockaddr_t));
  addrlen = sizeof(sockaddr_t);
  RELEASE_GIL();
  sock = lwip_accept(sock, &clientaddr, &addrlen);
  ACQUIRE_GIL();
  if (sock < 0)
    return ERR_IOERROR_EXC;
  addr.port = clientaddr.sin_port;
  addr.ip = clientaddr.sin_addr.s_addr;

  printf("CMD_ACCEPT: %i\r\n", sock);
  vosThSleep(TIME_U(100, MILLIS));
  PTuple *tpl = (PTuple *) psequence_new(PTUPLE, 2);
  PTUPLE_SET_ITEM(tpl, 0, PSMALLINT_NEW(sock));
  PObject *ipo = netaddress_to_object(&addr);
  PTUPLE_SET_ITEM(tpl, 1, ipo);
  *res = tpl;
  printf("CMD_ACCEPT: %i\r\n", sock);
  vosThSleep(TIME_U(100, MILLIS));
  return ERR_OK;
}


C_NATIVE(esp_wifi_select) {
  C_NATIVE_UNWARN();
  int32_t timeout;
  int32_t tmp, i, j, sock = -1;

  if (nargs < 4)
    return ERR_TYPE_EXC;

  fd_set rfd;
  fd_set wfd;
  fd_set xfd;
  struct timeval tms;
  struct timeval *ptm;
  PObject *rlist = args[0];
  PObject *wlist = args[1];
  PObject *xlist = args[2];
  fd_set *fdsets[3] = {&rfd, &wfd, &xfd};
  PObject *slist[3] = {rlist, wlist, xlist};
  PObject *tm = args[3];


  if (tm == MAKE_NONE()) {
    ptm = NULL;
  } else if (IS_PSMALLINT(tm)) {
    timeout = PSMALLINT_VALUE(tm);
    if (timeout < 0)
      return ERR_TYPE_EXC;
    tms.tv_sec = timeout / 1000;
    tms.tv_usec = (timeout % 1000) * 1000;
    ptm = &tms;
  } else return ERR_TYPE_EXC;

  for (j = 0; j < 3; j++) {
    tmp = PTYPE(slist[j]);
    if (!IS_OBJ_PSEQUENCE_TYPE(tmp))
      return ERR_TYPE_EXC;
    FD_ZERO (fdsets[j]);
    for (i = 0; i < PSEQUENCE_ELEMENTS(slist[j]); i++) {
      PObject *fd = PSEQUENCE_OBJECTS(slist[j])[i];
      if (IS_PSMALLINT(fd)) {
        //printf("%i -> %i\n",j,PSMALLINT_VALUE(fd));
        FD_SET(PSMALLINT_VALUE(fd), fdsets[j]);
        if (PSMALLINT_VALUE(fd) > sock)
          sock = PSMALLINT_VALUE(fd);
      } else return ERR_TYPE_EXC;
    }
  }

  printf("maxsock %i\n", sock);
  RELEASE_GIL();
  tmp = lwip_select( (sock + 1), fdsets[0], fdsets[1], fdsets[2], ptm );
  ACQUIRE_GIL();

  printf("result: %i\n", tmp);

  if (tmp < 0) {
    return ERR_IOERROR_EXC;
  }

  PTuple *tpl = (PTuple *) psequence_new(PTUPLE, 3);
  for (j = 0; j < 3; j++) {
    tmp = 0;
    for (i = 0; i <= sock; i++) {
      if (FD_ISSET(i, fdsets[j])) tmp++;
    }
    PTuple *rtpl = psequence_new(PTUPLE, tmp);
    tmp = 0;
    for (i = 0; i <= sock; i++) {
      //printf("sock %i in %i = %i\n",i,j,FD_ISSET(i, fdsets[j]));
      if (FD_ISSET(i, fdsets[j])) {
        PTUPLE_SET_ITEM(rtpl, tmp, PSMALLINT_NEW(i));
        tmp++;
      }
    }
    PTUPLE_SET_ITEM(tpl, j, rtpl);
  }
  *res = tpl;
  return ERR_OK;
}


VSemaphore scan_sem;
PDict *scan_dict;
PBytes *bssid_temp;
void *scanres;
int scansec = -1;

int __ssidlen(uint8_t* ssid){
  int i = 0;
  for(i=0;i<32;i++){
    if(!ssid[i]) break;
  }
  return i;
}

void scan_done(void *arg, STATUS status){
  if (status == OK) scanres=arg;  
  else scanres=NULL;
  vosSemSignalIsr(scan_sem);
}

void scan_gather(void *arg){
    struct bss_info *bss_link = (struct bss_info *)arg;
    bss_link = bss_link->next.stqe_next;//ignore the first one , it's invalid.

    while (bss_link != NULL){
      PObject *bssid = bssid_temp;
      __memcpy(PSEQUENCE_BYTES(bssid), bss_link->bssid, 6);

      if (pdict_get(scan_dict, bssid)) {
          continue;
      }
  
      //printf("bssid not in dict\n");
      //printf("ssidlen %i\n",__ssidlen(bss_link->ssid));

      scansec=-1;
      switch(bss_link->authmode){
        case AUTH_OPEN: scansec=0;break;
        case AUTH_WEP: scansec=1;break;
        case AUTH_WPA_PSK: scansec=2;break;
        default:
          scansec=3;
          break;
      }

      //printf("%x %i - %x %i\n",&sec,sec,&bss_link->rssi,bss_link->rssi);
      PTuple * res = ptuple_new(4, NULL);
      bssid = pbytes_new(6, bss_link->bssid);
      PTUPLE_SET_ITEM(res, 0, pstring_new(__ssidlen(bss_link->ssid), bss_link->ssid));
      PTUPLE_SET_ITEM(res, 1, PSMALLINT_NEW(scansec));
      PTUPLE_SET_ITEM(res, 2, PSMALLINT_NEW(bss_link->rssi));
      PTUPLE_SET_ITEM(res, 3, bssid);
      pdict_put(scan_dict, bssid, res);
      bss_link = bss_link->next.stqe_next;

    }
}

C_NATIVE(esp_turn_ap_off) {
  C_NATIVE_UNWARN();
  struct softap_config config;

  if(!wifi_set_opmode_current(STATIONAP_MODE))
    return ERR_IOERROR_EXC;

  if(!wifi_softap_get_config_default(&config)){   // Get config first.
    return ERR_IOERROR_EXC;
  }
  
  *config.ssid=0;
  *config.password=0;
  config.ssid_len = 0;

  if(!wifi_softap_set_config_current(&config)){ 
    printf("exit1\n"); 
    return ERR_IOERROR_EXC;
  }

  if(!wifi_set_opmode_current(STATION_MODE))
    return ERR_IOERROR_EXC;

  return ERR_OK;
}

C_NATIVE(esp_turn_station_on) {
  C_NATIVE_UNWARN();
  uint32_t m;
  m = wifi_get_opmode();
  if (m != STATION_MODE){
    printf("turn on station\n");
    if(!wifi_station_start())
      return ERR_IOERROR_EXC;
  }
  *res = m;
  return ERR_OK;
}

C_NATIVE(esp_turn_station_off) {
  C_NATIVE_UNWARN();
  uint32_t m;
  m = wifi_get_opmode();
  if (m != STATION_MODE){
    printf("turn off station\n");
    if(!wifi_station_stop())
      return ERR_IOERROR_EXC;
  }
  *res = m;
  return ERR_OK;
}

C_NATIVE(esp_wifi_scan) {
  C_NATIVE_UNWARN();
  int32_t time;
  int32_t i;
  uint32_t m;

  printf("SCAN %i\n",PTYPE(args[0]));
  if (parse_py_args("i", nargs, args, &time) != 1)
    return ERR_TYPE_EXC;

  scan_sem = vosSemCreate(0);
  scan_dict = pdict_new(16);
  bssid_temp = pbytes_new(6, NULL);
  //wiced_scan_result_t* result_ptr = (wiced_scan_result_t *) &result_buff;


  RELEASE_GIL();
  scanres=NULL;
  if(!wifi_station_scan(NULL,scan_done)){
    printf("bad scan\n");
    vosSemDestroy(scan_sem);
    ACQUIRE_GIL();
    return ERR_IOERROR_EXC;
  }
  printf("got here\n");
  vosSemWait(scan_sem);
  if(scanres){

  } else {
    printf("bad scan!\n");
    vosSemDestroy(scan_sem);
    ACQUIRE_GIL();
    return ERR_IOERROR_EXC;
  }
  printf("good scan\n");
  scan_gather(scanres);
  ACQUIRE_GIL();
  vosSemDestroy(scan_sem);
  printf("results %i\n", PDICT_ELEMENTS(scan_dict)); 
  *res = ptuple_new(PDICT_ELEMENTS(scan_dict), NULL);
  GC_START_STAGING();
  for (i = 0; i < PDICT_ELEMENTS(scan_dict); i++) {
    PObject *tpl = PDICT_VAL(scan_dict, i);
    GC_UNSTAGE(tpl); //must be unstaged, it was created in a non Python thread
    GC_UNSTAGE(PTUPLE_ITEM(tpl, 0));
    GC_UNSTAGE(PTUPLE_ITEM(tpl, 3));
    PTUPLE_SET_ITEM(*res, i, tpl);
  }

  GC_STOP_STAGING();
  return ERR_OK;
}

C_NATIVE(esp_softap_init){
  NATIVE_UNWARN();
  uint8_t *ssid;
  int sidlen, sec, passlen, max_conn;
  uint8_t *password;
  int32_t err;

  *res = MAKE_NONE();

  err = wifi_station_stop();
  if(!err)
    return ERR_IOERROR_EXC;

  if (parse_py_args("sisi", nargs, args,
                      &ssid, &sidlen,
                      &sec,
                      &password, &passlen,
                      &max_conn) != 4)
    return ERR_TYPE_EXC;
  
  printf("args: %s %s %i %i\n", ssid, password, sidlen, passlen);
  
  err = wifi_set_opmode_current(STATIONAP_MODE);
  if(!err)
    return ERR_IOERROR_EXC;

  struct softap_config config;

  if(!wifi_softap_get_config(&config)){   // Get config first.
    return ERR_IOERROR_EXC;
  }
  // printf("init_config: %s %s %i\n", config.ssid, config.password, config.ssid_len);
  __memcpy(config.ssid, ssid, sidlen);
  __memcpy(config.password, password, passlen);
  config.ssid[sidlen]=0;
  config.password[passlen]=0;
  config.authmode = sec;
  config.ssid_len = sidlen;
  //config.channel = 0;
  config.max_connection = max_conn;

  if(!wifi_softap_dhcps_stop())
    return ERR_IOERROR_EXC;

  if(!wifi_softap_set_config_current(&config))
    return ERR_IOERROR_EXC;

  if(!wifi_softap_dhcps_start())
    return ERR_IOERROR_EXC;

  return ERR_OK;
}

C_NATIVE(esp_softap_config){
  NATIVE_UNWARN();
  struct ip_info info;
  NetAddress ip, gw, net;

  if (parse_py_args("nnn", nargs, args,
                      &ip,
                      &gw,
                      &net) != 3)
    return ERR_TYPE_EXC;

  printf("set ip\n");
  if(!wifi_softap_dhcps_stop()){
    printf("exit3\n"); 
    return ERR_IOERROR_EXC;
  }
  info.ip.addr = ip.ip;      
  info.gw.addr =  gw.ip;     
  info.netmask.addr = net.ip;
  if(!wifi_set_ip_info(SOFTAP_IF, &info)){
    printf("exit4\n"); 
    return ERR_IOERROR_EXC;
  }

  if(!wifi_softap_dhcps_start()){
    printf("exit5\n"); 
    return ERR_IOERROR_EXC;
  }
    
  if(!wifi_get_ip_info(SOFTAP_IF, &info))
    return ERR_TYPE_EXC;

  printf("%x %x %x\n", info.ip.addr, info.netmask.addr, info.gw.addr);

  return ERR_OK;
}

C_NATIVE(esp_softap_get_info){
  NATIVE_UNWARN();

  struct softap_config config;

  if(!wifi_softap_get_config(&config)){   // Get config first.
    return ERR_IOERROR_EXC;
  }

  struct station_info *info;
  NetAddress addr;
  addr.port = 0;
  PObject *mac = psequence_new(PBYTES, 6);
  
  PTuple *tpl = psequence_new(PTUPLE, config.max_connection);
  
  int i = 0;
  info = wifi_softap_get_station_info();

  for(i = 0; i < config.max_connection; i++) {
    printf("connection %i\n",i);
    PTuple *apc = psequence_new(PTUPLE, 2);
    if (info != NULL){
      printf("--> bssid %x:%x:%x:%x:%x:%x, ip %x\n", info->bssid[0], info->bssid[1], info->bssid[2], info->bssid[3], info->bssid[4], info->bssid[5], info->ip.addr);
      addr.ip = info->ip.addr;
      mac = pbytes_new(6, info->bssid);
      PTUPLE_SET_ITEM(apc, 0, netaddress_to_object(&addr));
      PTUPLE_SET_ITEM(apc, 1, mac);
      PTUPLE_SET_ITEM(tpl, i, apc);
      info = info->next.stqe_next;
    }
  }

  *res = tpl;
  return ERR_OK;  
}
