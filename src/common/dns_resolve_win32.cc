// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2019 SUSE LINUX GmbH
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#include <ws2tcpip.h>
#include <winsock2.h>
#include <windows.h>
#include <windns.h>

#include "include/scope_guard.h"
#include "dns_resolve.h"
#include "common/debug.h"

#define dout_subsys ceph_subsys_


namespace ceph {

int ResolvHWrapper::res_query(const char *hostname, int cls,
    int type, u_char *buf, int bufsz) {
  return -1;
}

int ResolvHWrapper::res_search(const char *hostname, int cls,
    int type, u_char *buf, int bufsz) {
  return -1;
}

DNSResolver::~DNSResolver()
{
  delete resolv_h;
}

int DNSResolver::resolve_cname(CephContext *cct, const string& hostname,
    string *cname, bool *found)
{
  *found = false;
  const char* origname = hostname.c_str();
  PDNS_RECORDA responses = NULL;
  DNS_STATUS dnsstatus = 0;

  dnsstatus = DnsQuery_A(origname, DNS_TYPE_CNAME, DNS_QUERY_STANDARD, NULL,
		  &responses, NULL);
  if (dnsstatus != ERROR_SUCCESS) {
    lderr(cct) << "DnsQuery_A() failed with last_error()= " << dnsstatus
	    << dendl;
    return -1;
  }

  PDNS_RECORDA currentEntry = responses;
  while (currentEntry) {
    if (currentEntry->wType == DNS_TYPE_CNAME) {
      ldout(cct, 20) << "cname host=" << currentEntry->Data.CNAME.pNameHost
	      << dendl;
      *cname = currentEntry->Data.CNAME.pNameHost;
      *found = true;
      DnsRecordListFree(responses, DnsFreeRecordList);
      return 0;
    }
  currentEntry = currentEntry->pNext;
  }

  DnsRecordListFree(responses, DnsFreeRecordList);
  return -EINVAL;
}

int DNSResolver::resolve_ip_addr(CephContext *cct, const string& hostname,
    entity_addr_t *addr)
{
  int family = cct->_conf->ms_bind_ipv6 ? AF_INET6 : AF_INET;
  int type = cct->_conf->ms_bind_ipv6 ? DNS_TYPE_AAAA : DNS_TYPE_A;
  PDNS_RECORDA responses = NULL;
  DNS_STATUS dnsstatus = 0;
  char addr_buf[64];
  memset(addr_buf, 0, sizeof(addr_buf));

  dnsstatus = DnsQuery_A(hostname.c_str(), type, DNS_QUERY_STANDARD, NULL,
		  &responses, NULL);
  if (dnsstatus != ERROR_SUCCESS) {
    lderr(cct) << "DnsQuery_A() failed with last_error()= " << dnsstatus
            << dendl;
    return -1;
  }

  PDNS_RECORDA currentEntry = responses;
  while (currentEntry) {
	  if (currentEntry->wType == type && type == DNS_TYPE_A) {
		 if (!inet_ntop(family, &currentEntry->Data.A.IpAddress,
					  addr_buf, sizeof(addr_buf))) {
			 lderr(cct) << "inet_ntop failed with WSA last_error()"
				 << "= " << WSAGetLastError() << dendl;
			 DnsRecordListFree(responses, DnsFreeRecordList);
			 return -1;
		  }
	  } else if (currentEntry->wType == type && type ==  DNS_TYPE_AAAA) {
		 if (!inet_ntop(family, &currentEntry->Data.AAAA.Ip6Address,
					 addr_buf, sizeof(addr_buf))) {
			 lderr(cct) << "inet_ntop failed with WSA last_error()"
				 << "= " << WSAGetLastError() << dendl;
			 DnsRecordListFree(responses, DnsFreeRecordList);
			 return -1;
		 }
	  }
	  currentEntry = currentEntry->pNext;
  }

  if (!addr->parse(addr_buf)) {
	  lderr(cct) << "failed to parse address '" << addr_buf << "'"
		  << dendl;
	  DnsRecordListFree(responses, DnsFreeRecordList);
	  return -1;
  }

  DnsRecordListFree(responses, DnsFreeRecordList);
  return 0;
}

int DNSResolver::resolve_srv_hosts(CephContext *cct, const string& service_name,
    const SRV_Protocol trans_protocol,
    map<string, DNSResolver::Record> *srv_hosts)
{
  return this->resolve_srv_hosts(cct, service_name, trans_protocol, "", srv_hosts);
}

int DNSResolver::resolve_srv_hosts(CephContext *cct, const string& service_name,
    const SRV_Protocol trans_protocol, const string& domain,
    map<string, DNSResolver::Record> *srv_hosts)
{
  PDNS_RECORDA responses = NULL;
  DNS_STATUS dnsstatus = 0;
  string proto_str = srv_protocol_to_str(trans_protocol);
  string query_str = "_"+service_name+"._"+proto_str+(domain.empty() ? ""
		  : "."+domain);
  char full_target[1025]; //NS_MAXDNAME

  dnsstatus = DnsQuery_A(query_str.c_str(), DNS_TYPE_SRV, DNS_QUERY_STANDARD, NULL, &responses, NULL);
  if (dnsstatus != ERROR_SUCCESS) {
	  lderr(cct) << "DnsQuery_A() failed with last_error()= " << dnsstatus
		  << dendl;
	  return -1;
  }

  PDNS_RECORDA currentEntry = responses;
  while (currentEntry) {
	  if (currentEntry->wType == DNS_TYPE_SRV) {
		  uint16_t priority = currentEntry->Data.SRV.wPriority;
		  uint16_t weight = currentEntry->Data.SRV.wWeight;
		  uint16_t port = currentEntry->Data.SRV.wPort;
		  entity_addr_t addr;
		  memcpy(full_target, currentEntry->Data.SRV.pNameTarget,
				  strlen(currentEntry->Data.SRV.pNameTarget)+1);
		  if (this->resolve_ip_addr(cct, full_target, &addr)
				  == 0) {
			  addr.set_port(port);
			  (*srv_hosts)[full_target] = {priority, weight, addr};
		  }
	  }
	  currentEntry = currentEntry->pNext;
  }

  DnsRecordListFree(responses, DnsFreeRecordList);
  return 0;
}

}
