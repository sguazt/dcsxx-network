/**
 * \file dcs/network/pcap/pcap.hpp
 *
 * \brief Collections of classes and function based on the libpcap library.
 *
 * \author Marco Guazzone (marco.guazzone@gmail.com)
 *
 * <hr/>
 *
 * Copyright (C) 2012       Marco Guazzone (marco.guazzone@gmail.com)
 *                          [Distributed Computing System (DCS) Group,
 *                           Computer Science Institute,
 *                           Department of Science and Technological Innovation,
 *                           University of Piemonte Orientale,
 *                           Alessandria (Italy)]
 *
 * This file is part of dcsxx-network (below referred to as "this program").
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef DCS_NETWORK_PCAP_PCAP_HPP
#define DCS_NETWORK_PCAP_PCAP_HPP


#include <algorithm>
#include <arpa/inet.h>
#include <boost/smart_ptr.hpp>
#include <boost/cstdint.hpp>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <dcs/assert.hpp>
#include <dcs/debug.hpp>
#include <dcs/exception.hpp>
#include <dcs/logging.hpp>
#include <dcs/network/byte_order.hpp>
#include <dcs/network/ethernet.hpp>
//#include <dcs/network/ip.hpp>
#include <iostream>
#include <iomanip>
//#include <netinet/ether.h>
#include <netinet/in.h>
//#include <netinet/ip.h>
#include <pcap/pcap.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/time.h>


namespace dcs { namespace network { namespace pcap {

inline
std::string lookup_device()
{
	char ebuf[PCAP_ERRBUF_SIZE];

	char* dev = ::pcap_lookupdev(ebuf);
	if (!dev)
	{
		std::ostringstream oss;
		oss << "Couldn't find a default device: " << ebuf;
		DCS_EXCEPTION_THROW(std::runtime_error, oss.str());
	}

	return std::string(dev);
}

inline
::pcap_if_t* find_all_devices()
{
	char ebuf[PCAP_ERRBUF_SIZE];
	::pcap_if_t* devs(0);

	if (::pcap_findalldevs(&devs, ebuf) == -1)
	{
		std::ostringstream oss;
		oss << "Couldn't find a default device: " << ebuf;
		DCS_EXCEPTION_THROW(std::runtime_error, oss.str());
	}

	return devs;
}

inline
void free_devices(::pcap_if_t* devs)
{
	::pcap_freealldevs(devs);
}

/*
class base_packet
{
	public: virtual ~base_packet()
	{
	}

	public: virtual ::boost::uint8_t const* payload() const = 0;
}; // base_packet
*/


class raw_packet
{
	public: raw_packet()
	{
	}

	public: raw_packet(pcap_pkthdr const& hdr, ::u_char const* dat)
	: hdr_(hdr),
	  data_(0)
	{
		if (dat)
		{
			const ::boost::uint32_t sz(hdr.caplen);
			data_ = new ::boost::uint8_t[sz];
			::std::copy(dat, dat+sz, data_);
		}
	}

	public: ~raw_packet()
	{
		if (data_)
		{
			delete[] data_;
		}
	}

	public: timeval const& capture_timestamp() const
	{
		return hdr_.ts;
	}

	public: ::boost::uint32_t capture_size() const
	{
		return hdr_.caplen;
	}

	public: ::boost::uint32_t size() const
	{
		return hdr_.len;
	}

	public: ::boost::uint8_t const* data() const
	{
		return data_;
	}


	private: ::pcap_pkthdr hdr_;
	private: ::boost::uint8_t* data_;
}; // raw_packet

template <typename CharT, typename CharTraitsT>
::std::basic_ostream<CharT,CharTraitsT>& operator<<(::std::basic_ostream<CharT,CharTraitsT>& os, raw_packet const& pkt)
{
	::boost::uint32_t n = pkt.capture_size();

	os << "[" << pkt.capture_timestamp().tv_sec << "|" << n << "|" << pkt.size() << "|";
	::boost::uint8_t const* data = pkt.data();
	for (::boost::uint32_t i = 0; i < n; ++i)
	{
		os << ::std::hex << data[i] << ::std::dec;
	}
	os << "]";

	return os;
}

/*
class ethernet_packet: public base_packet
{
	public: static const ::boost::uint8_t address_size = 6; ///< Octects in one MAC address
	public: static const ::boost::uint8_t header_size = 14; ///< Total octects in header
	public: static const ::boost::uint8_t header_8021q_size = 4; ///< Octects in the optional 802.1q tag
	public: static const ::boost::uint16_t mtu = 1500; ///< Max octects in payload
	public: static const ::boost::uint8_t min_frame_size = 60; ///< Min octects in frame sans FCS
	public: static const ::boost::uint16_t max_frame_size = header_size+mtu; ///< Max octects in frame sans FCS
	public: static const ::boost::uint8_t fcs_size = 4; ///< Octects in the FCS
//	// Ethernet protocol ID's (taken from linux/if_ether.h)
//	public: static const ::boost::uint16_t type_loop = 0x0060; ///<Ethernet Loopback packet
//	public: static const ::boost::uint16_t type_pup = 0x0200; ///<Xerox PUP packet
//	public: static const ::boost::uint16_t type_pupat = 0x0201; ///<Xerox PUP Addr Trans packet
//	public: static const ::boost::uint16_t type_ip = 0x0800; ///<Internet Protocol packet
//	public: static const ::boost::uint16_t type_x25 = 0x0805; ///<CCITT X.25
//	public: static const ::boost::uint16_t type_arp = 0x0806; ///<Address Resolution packet
//	public: static const ::boost::uint16_t type_bpq = 0x08ff; ///<G8BPQ AX.25 Ethernet Packet    [ NOT AN OFFICIALLY REGISTERED ID ]
//	public: static const ::boost::uint16_t type_ieeepup = 0x0a00; ///<Xerox IEEE802.3 PUP packet
//	public: static const ::boost::uint16_t type_ieeepupat = 0x0a01; ///<Xerox IEEE802.3 PUP Addr Trans packet
//	public: static const ::boost::uint16_t type_dec = 0x6000; ///< DEC Assigned proto
//	public: static const ::boost::uint16_t type_dna_dl = 0x6001; ///< DEC DNA Dump/Load
//	public: static const ::boost::uint16_t type_dna_rc = 0x6002; ///< DEC DNA Remote Console
//	public: static const ::boost::uint16_t type_dna_rt = 0x6003; ///< DEC DNA Routing
//	public: static const ::boost::uint16_t type_lat = 0x6004; ///< DEC LAT
//	public: static const ::boost::uint16_t type_diag = 0x6005; ///< DEC Diagnostics
//	public: static const ::boost::uint16_t type_cust = 0x6006; ///< DEC Customer use
//	public: static const ::boost::uint16_t type_sca = 0x6007; ///< DEC Systems Comms Arch
//	public: static const ::boost::uint16_t type_teb = 0x6558; ///< Trans Ether Bridging
//	public: static const ::boost::uint16_t type_rarp = 0x8035; ///<Reverse Addr Res packet
//	public: static const ::boost::uint16_t type_atalk = 0x809b; ///<Appletalk DDP
//	public: static const ::boost::uint16_t type_aarp = 0x80f3; ///<Appletalk AARP
//	public: static const ::boost::uint16_t type_8021q = 0x8100; ///<802.1Q VLAN Extended Header
//	public: static const ::boost::uint16_t type_ipx = 0x8137; ///<IPX over DIX
//	public: static const ::boost::uint16_t type_ipv6 = 0x86dd; ///<IPv6 over bluebook
//	public: static const ::boost::uint16_t type_pause = 0x8808; ///<IEEE Pause frames. See 802.3 31B
//	public: static const ::boost::uint16_t type_slow = 0x8809; ///<Slow Protocol. See 802.3ad 43B
//	public: static const ::boost::uint16_t type_wccp = 0x883e; ///<Web-cache coordination proto defined in draft-wilson-wrec-wccp-v2-00.txt
//	public: static const ::boost::uint16_t type_ppp_disc = 0x8863; ///<PPPoE discovery messages
//	public: static const ::boost::uint16_t type_ppp_ses = 0x8864; ///<PPPoE session messages
//	public: static const ::boost::uint16_t type_mpls_uc = 0x8847; ///<MPLS Unicast traffic
//	public: static const ::boost::uint16_t type_mpls_mc = 0x8848; ///<MPLS Multicast traffic
//	public: static const ::boost::uint16_t type_atmmpoa = 0x884c; ///<MultiProtocol Over ATM
//	public: static const ::boost::uint16_t type_link_ctl = 0x886c; ///< HPNA, wlan link local tunnel
//	public: static const ::boost::uint16_t type_atmfate = 0x8884; ///<Frame-based ATM Transp over Ethernet
//	public: static const ::boost::uint16_t type_pae = 0x888e; ///< Port Access Entity (IEEE 802.1X)
//	public: static const ::boost::uint16_t type_aoe = 0x88a2; ///<ATA over Ethernet
//	public: static const ::boost::uint16_t type_8021ad = 0x88a8; ///< 802.1ad Service VLAN
//	public: static const ::boost::uint16_t type_802_ex1 = 0x88b5; ///< 802.1 Local Experimental 1
//	public: static const ::boost::uint16_t type_tipc = 0x88ca; ///< TIPC
//	public: static const ::boost::uint16_t type_8021ah = 0x88e7; ///< 802.1ah Backbone Service Tag
//	public: static const ::boost::uint16_t type_1588 = 0x88f7; ///< IEEE 1588 Timesync
//	public: static const ::boost::uint16_t type_fcoe = 0x8906; ///< Fibre Channel over Ethernet
//	public: static const ::boost::uint16_t type_tdls = 0x890d; ///< TDLS
//	public: static const ::boost::uint16_t type_fip = 0x8914; ///< FCoE Initialization Protocol
//	public: static const ::boost::uint16_t type_qinq1 = 0x9100; ///< deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ]
//	public: static const ::boost::uint16_t type_qinq2 = 0x9200; ///< deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ]
//	public: static const ::boost::uint16_t type_qinq3 = 0x9300; ///< deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ]
//	public: static const ::boost::uint16_t type_edsa = 0xdada; ///< Ethertype DSA [ NOT AN OFFICIALLY REGISTERED ID ]
//	public: static const ::boost::uint16_t type_af_iucv = 0xfbfb; ///< IBM af_iucv [ NOT AN OFFICIALLY REGISTERED ID ]
//	// Non DIX types. Won't clash for 1500 types.
//	public: static const ::boost::uint16_t type_802_3 = 0x0001; ///< Dummy type for 802.3 frames
//	public: static const ::boost::uint16_t type_ax25 = 0x0002; ///< Dummy protocol id for AX.25
//	public: static const ::boost::uint16_t type_all = 0x0003; ///< Every packet (be careful!!!)
//	public: static const ::boost::uint16_t type_802_2 = 0x0004; ///< 802.2 frames
//	public: static const ::boost::uint16_t type_snap = 0x0005; ///< Internal only
//	public: static const ::boost::uint16_t type_ddcmp = 0x0006; ///< DEC DDCMP: Internal only
//	public: static const ::boost::uint16_t type_wan_ppp = 0x0007; ///< Dummy type for WAN PPP frames
//	public: static const ::boost::uint16_t type_ppp_mp = 0x0008; ///< Dummy type for PPP MP frames
//	public: static const ::boost::uint16_t type_localtalk = 0x0009; ///< Localtalk pseudo type
//	public: static const ::boost::uint16_t type_can = 0x000C; ///< CAN: Controller Area Network
//	public: static const ::boost::uint16_t type_canfd = 0x000D; ///< CANFD: CAN flexible data rate
//	public: static const ::boost::uint16_t type_ppptalk = 0x0010; ///< Dummy type for Atalk over PPP
//	public: static const ::boost::uint16_t type_tr_802_2 = 0x0011; ///< 802.2 frames
//	public: static const ::boost::uint16_t type_mobitex = 0x0015; ///< Mobitex (kaz@cafe.net)
//	public: static const ::boost::uint16_t type_control = 0x0016; ///< Card specific control frames
//	public: static const ::boost::uint16_t type_irda = 0x0017; ///< Linux-IrDA
//	public: static const ::boost::uint16_t type_econet = 0x0018; ///< Acorn Econet
//	public: static const ::boost::uint16_t type_hdlc = 0x0019; ///< HDLC frames
//	public: static const ::boost::uint16_t type_arcnet = 0x001A; ///< 1A for ArcNet :-)
//	public: static const ::boost::uint16_t type_dsa = 0x001B; ///< Distributed Switch Arch
//	public: static const ::boost::uint16_t type_trailer = 0x001C; ///< Trailer switch tagging
//	public: static const ::boost::uint16_t type_phonet = 0x00F5; ///< Nokia Phonet frames
//	public: static const ::boost::uint16_t type_ieee802154 = 0x00F6; ///< IEEE802.15.4 frame
//	public: static const ::boost::uint16_t type_caif = 0x00F7; ///< ST-Ericsson CAIF protocol
	// Taken from net/ethernet.h. See also: http://standards.ieee.org/develop/regauth/ethertype/eth.txt
	public: static const ::boost::uint16_t ethertype_pup = 0x0200; ///< Xeror PUP
	public: static const ::boost::uint16_t ethertype_sprite = 0x0500; ///< Sprite
	public: static const ::boost::uint16_t ethertype_ip = 0x0800; ///< IP
	public: static const ::boost::uint16_t ethertype_arp = 0x0806; ///< Address resolution
	public: static const ::boost::uint16_t ethertype_rarp = 0x8035; ///< Reverse ARP
	public: static const ::boost::uint16_t ethertype_atalk = 0x809B; ///< AppleTalk protocol (Ethertalk)
	public: static const ::boost::uint16_t ethertype_aarp = 0x80F3; ///< AppleTalk ARP
	public: static const ::boost::uint16_t ethertype_ieee8021q = 0x8100; ///< IEEE 802.1Q VLAN extended header
	public: static const ::boost::uint16_t ethertype_ipx = 0x8137; ///< IPX
	public: static const ::boost::uint16_t ethertype_ipv6 = 0x86dd; ///< IP protocol version 6
	public: static const ::boost::uint16_t ethertype_loopback = 0x9000; ///< Configuration testing protocol
	public: static const ::boost::uint16_t ethertype_ieee8021qinq1 = 0x9100; ///< Deprecated IEEE 802.1QinQ VLAN tagging
	public: static const ::boost::uint16_t ethertype_ieee8021qinq2 = 0x9200; ///< Deprecated IEEE 802.1QinQ VLAN tagging
	public: static const ::boost::uint16_t ethertype_ieee8021qinq3 = 0x9300; ///< Deprecated IEEE 802.1QinQ VLAN tagging
	public: static const ::boost::uint16_t ethertype_ieee8021ad = 0x88a8; ///< IEEE 802.1ad Service VLAN


	//private: struct ethernet_address
	//{
	//	::boost::uint8_t addr_[address_size]; ///< Address
	//};

	/// The Ethernet header
	private: struct ethernet_header
	{
		::boost::uint8_t dst_addr_[address_size]; ///< Destination address
		::boost::uint8_t src_addr_[address_size]; ///<  Source address
		::boost::uint16_t type_; ///<  Packet type ID
	};

	/// The optional IEEE 802.1q tag
	private: struct ethernet_8021q_header
	{
		uint16_t tpid_; ///< Tag Protocol Identifier
		uint16_t tci_; ///< Tag Control Identifier
	};

	public: ethernet_packet(raw_packet const& pkt)
	{
		parse_data(pkt.data(), pkt.capture_size());
	}

	public: ethernet_packet(::boost::uint8_t const* pkt, ::boost::uint32_t sz)
	{
		parse_data(pkt, sz);
	}

	public: virtual ::boost::uint8_t const* payload() const
	{
		return p_data_;
	}

	public: ::boost::uint8_t const* source_address() const
	{
		return p_hdr_->src_addr_;
	}

	public: ::boost::uint8_t const* destination_address() const
	{
		return p_hdr_->dst_addr_;
	}

	public: ::boost::uint32_t type() const
	{
		return ::dcs::network::byte_order< ::boost::uint16_t >::network_to_host(p_hdr_->type_);
	}

	private: void parse_data(::boost::uint8_t const* p_data, ::boost::uint32_t sz)
	{
		DCS_ASSERT(header_size <= sz,
				   DCS_EXCEPTION_THROW(::std::logic_error,
									   "Not enough space for Ethernet header"));

		p_hdr_ = reinterpret_cast<ethernet_header const*>(p_data);
		::boost::uint32_t payload_pos = header_size;

		::boost::uint16_t type = ::dcs::network::byte_order< ::boost::uint16_t >::network_to_host(p_hdr_->type_);
		if (type == ethertype_ieee8021ad
			|| type == ethertype_ieee8021q
			|| type == ethertype_ieee8021qinq1
			|| type == ethertype_ieee8021qinq2
			|| type == ethertype_ieee8021qinq3)
		{
			DCS_ASSERT((header_size+header_8021q_size) <= sz,
					   DCS_EXCEPTION_THROW(::std::logic_error,
										   "Not enough space for Ethernet header and 802.1q tag"));

			p_hdr_8021q_ = reinterpret_cast<ethernet_8021q_header const*>(p_data+header_size);
			payload_pos += header_8021q_size;
		}

		p_data_ = p_data+payload_pos;
	}


	private: ethernet_header const* p_hdr_;
	private: ethernet_8021q_header const* p_hdr_8021q_;
	private: ::boost::uint8_t const* p_data_;
}; // ethernet_packet

template <typename CharT, typename CharTraitsT>
::std::basic_ostream<CharT,CharTraitsT>& operator<<(::std::basic_ostream<CharT,CharTraitsT>& os, ethernet_packet const& pkt)
{
	os	<< ::ether_ntoa(reinterpret_cast< ::ether_addr const* >(pkt.source_address()))
		<< " > "
		<< ::ether_ntoa(reinterpret_cast< ::ether_addr const* >(pkt.destination_address()))
		<< ", ";

	if (pkt.type() <= ethernet_packet::mtu)
	{
		os << "IEEE 802.3";
	}
	else
	{
		switch (pkt.type())
		{
			case ethernet_packet::ethertype_pup:
				os << "PUP";
				break;
			case ethernet_packet::ethertype_sprite:
				os << "Sprite";
				break;
			case ethernet_packet::ethertype_ip:
				os << "IPv4";
				break;
			case ethernet_packet::ethertype_arp:
				os << "ARP";
				break;
			case ethernet_packet::ethertype_rarp:
				os << "Reverse ARP";
				break;
			case ethernet_packet::ethertype_atalk:
				os << "Appletalk";
				break;
			case ethernet_packet::ethertype_aarp:
				os << "Appletalk ARP";
				break;
			case ethernet_packet::ethertype_ieee8021q:
				os << "IEEE 802.1q";
				break;
			case ethernet_packet::ethertype_ipx:
				os << "IPX";
				break;
			case ethernet_packet::ethertype_ipv6:
				os << "IPv6";
				break;
			case ethernet_packet::ethertype_loopback:
				os << "Loopback";
				break;
			case ethernet_packet::ethertype_ieee8021qinq1:
				os << "IEEE 802.1QinQ (9100)";
				break;
			case ethernet_packet::ethertype_ieee8021qinq2:
				os << "IEEE 802.1QinQ (9200)";
				break;
			case ethernet_packet::ethertype_ieee8021qinq3:
				os << "IEEE 802.1QinQ (9300)";
				break;
			case ethernet_packet::ethertype_ieee8021ad:
				os << "IEEE 802.1ad";
				break;
			detault:
				os << "Unknown";
		}
	}

	return os;
}
*/

#if 0
class ip_packet: public base_packet
{
/// IP header
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

	public: ip_packet(byte_type* p_pkt)
	: p_pkt_(p_pkt)
	{
	}

	public: virtual byte_type* payload() const
	{
	}

	private: byte_type* p_pkt_;
}; // ip_packet

class tcp_packet: public base_packet
{
/* TCP header */
struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */

	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

	public: tcp_packet(byte_type* p_pkt)
	: p_pkt_(p_pkt)
	{
	}

	public: virtual byte_type* payload() const
	{
	}

	private: byte_type* p_pkt_;
}; // tcp_packet
#endif // 0


::boost::shared_ptr< ::dcs::network::ethernet_frame > make_ethernet_frame(raw_packet const& pkt)
{
	return ::boost::make_shared< ::dcs::network::ethernet_frame >(pkt.data(), ::std::min(pkt.capture_size(), pkt.size()));
}

//::boost::shared_ptr< ::dcs::network::ip_packet> make_ip_packet(raw_packet const& pkt)
//{
//}

/*
::boost::shared_ptr<tcp_packet> make_tcp_packet(raw_packet const& pkt)
{
}
*/

class base_packet_sniffer
{
	public: typedef ::pcap_t handle_type;
	public: typedef bpf_u_int32 uint32_type;


	public: static const uint32_type unknown_netmask = PCAP_NETMASK_UNKNOWN;


	public: base_packet_sniffer()
	: p_hnd_(0),
	  p_filt_(0),
	  filt_opt_(true),
	  filt_netmask_(unknown_netmask),
	  active_(false)
	{
	}

	public: virtual ~base_packet_sniffer()
	{
		close();
	}

	public: virtual void open() = 0;

	public: virtual void close()
	{
		if (p_filt_)
		{
			::pcap_freecode(p_filt_);
			delete p_filt_;
		}
		if (p_hnd_)
		{
			::pcap_close(p_hnd_);
		}
	}

	public: virtual ::boost::shared_ptr<raw_packet> capture()
	{
		if (!active_)
		{
			activate();

			// Compile and set the filter expression (if present)
			if (!filt_expr_.empty())
			{
				if (p_filt_)
				{
					delete p_filt_;
				}
				p_filt_ = new ::bpf_program;

				int ret(0);

				ret = ::pcap_compile(p_hnd_,
									 p_filt_,
									 filt_expr_.c_str(),
									 filt_opt_ ? 1 : 0,
									 filt_netmask_ != unknown_netmask ? filt_netmask_ : 0);
				if (ret < 0)
				{
					::std::ostringstream oss;
					oss << "Couldn't compile filter: " << ::pcap_geterr(p_hnd_);
					DCS_EXCEPTION_THROW(::std::logic_error, oss.str());
				}

				ret = ::pcap_setfilter(p_hnd_, p_filt_);
				if (ret < 0)
				{
					::std::ostringstream oss;
					oss << "Couldn't set filter: " << ::pcap_geterr(p_hnd_);
					DCS_EXCEPTION_THROW(::std::logic_error, oss.str());
				}
			}
			active_ = true;
		}

		::pcap_pkthdr* pkt_hdr(0);
		::u_char const* pkt_data(0);
		int ret = ::pcap_next_ex(this->native_handle(), &pkt_hdr, &pkt_data);
		if (ret == 0)
		{
			// timeout
			//TODO: what to do?
			return ::boost::shared_ptr<raw_packet>();
		}
		else if (ret < 0)
		{
			std::ostringstream oss;
			oss << "Couldn't capture packets: " << ::pcap_geterr(this->native_handle());
			DCS_EXCEPTION_THROW(::std::logic_error, oss.str());
		}

		return ::boost::make_shared<raw_packet>(*pkt_hdr, pkt_data);
	}

	public: void snapshot_length(int val)
	{
		DCS_ASSERT(val > 0,
				   DCS_EXCEPTION_THROW(::std::invalid_argument,
									   "Invalid snapshot length: expected a positive number"));

		int ret = ::pcap_set_snaplen(p_hnd_, val);
		if (ret == PCAP_ERROR_ACTIVATED)
		{
			DCS_EXCEPTION_THROW(::std::logic_error, "Capture handle has been already activated");
		}
	}

/*
	public: int snapshot_length() const
	{
		DCS_ASSERT(p_hnd_,
				   DCS_EXCEPTION_THROW(::std::logic_error,
									   "Capture handle is not set"));

		return p_hnd_->snapshot;
	}
*/

	public: void promiscuous_mode(bool val)
	{
		int ret = ::pcap_set_promisc(p_hnd_, val ? 1 : 0);
		if (ret == PCAP_ERROR_ACTIVATED)
		{
			DCS_EXCEPTION_THROW(::std::logic_error, "Capture handle has been already activated");
		}
	}

/*
	public: bool promiscuous_mode() const
	{
		DCS_ASSERT(p_hnd_,
				   DCS_EXCEPTION_THROW(::std::logic_error,
									   "Capture handle is not set"));

		return p_hnd_->opt.promisc ? true : false;
	}
*/

	public: void filter(::std::string const& expr, bool optimize = true, uint32_type netmask = unknown_netmask)
	{
		if (!p_filt_)
		{
			p_filt_ = new ::bpf_program;
		}

		if (::pcap_compile(p_hnd_, p_filt_, expr.c_str(), optimize ? 1 : 0, netmask) < 0)
		{
			::std::ostringstream oss;
			oss << "Couldn't compile filter '" << expr << "': " << ::pcap_geterr(p_hnd_);
			DCS_EXCEPTION_THROW(::std::logic_error, oss.str());
		}
/*
		if (::pcap_setfilter(p_hnd_, p_filt_) < 0)
		{
			::std::ostringstream oss;
			oss << "Couldn't set filter '" << expr << "': " << ::pcap_geterr(p_hnd_);
			DCS_EXCEPTION_THROW(::std::logic_error, oss.str());
		}
*/
	}

	public: handle_type* native_handle()
	{
		return p_hnd_;
	}

	public: handle_type const* native_handle() const
	{
		return p_hnd_;
	}

	protected: void native_handle(pcap_t* p_hnd)
	{
		p_hnd_ = p_hnd;
	}

	protected: virtual void activate() = 0;


	private: ::pcap_t* p_hnd_; ///< The pcap capture handle
	private: ::bpf_program* p_filt_; ///< The current packet filter
	private: ::std::string filt_expr_; ///< The filter expression
	private: bool filt_opt_; ///< Flag to control the filter compilation
	private: uint32_type filt_netmask_; ///< Netmask associated to the filter
	private: bool active_; ///< Tell if the sniffer has been already activated
}; // base_packet_sniffer

class live_packet_sniffer: public base_packet_sniffer
{
	private: typedef base_packet_sniffer base_type;


	public: live_packet_sniffer()
	: active_(false)
	{
	}

	public: live_packet_sniffer(::std::string const& dev)
	: active_(false)
	{
		open(dev);
	}

	public: void open(::std::string const& dev)
	{
		dev_ = dev;

		open();
	}

	public: void open()
	{
		char ebuf[PCAP_ERRBUF_SIZE];

		::pcap_t* p_hnd = ::pcap_create(dev_.c_str(), ebuf);
		if (!p_hnd)
		{
			std::ostringstream oss;
			oss << "Couldn't open a live capture handle for device " << dev_ << ": " << ebuf;
			DCS_EXCEPTION_THROW(std::runtime_error, oss.str());
		}

		::pcap_set_snaplen(p_hnd, 65535);
		::pcap_set_promisc(p_hnd, 1);
		::pcap_set_timeout(p_hnd, 1000);

		this->native_handle(p_hnd);
	}

	public: void close()
	{
		base_type::close();
		active_ = false;
	}

	public: void timeout(int val)
	{
		DCS_ASSERT(val > 0,
				   DCS_EXCEPTION_THROW(::std::invalid_argument,
									   "Invalid timeout: expected a positive number"));

		int ret = ::pcap_set_timeout(this->native_handle(), val);
		if (ret == PCAP_ERROR_ACTIVATED)
		{
			DCS_EXCEPTION_THROW(::std::logic_error, "Capture handle has been already activated");
		}
	}

/*
	public: int timeout() const
	{
		DCS_ASSERT(this->native_handle(),
				   DCS_EXCEPTION_THROW(::std::logic_error,
									   "Capture handle is not set"));

		return this->native_handle()->md.timeout;
	}
*/

	protected: void activate()
	{
		if (active_)
		{
			return;
		}

		int ret = ::pcap_activate(this->native_handle());
		if (!ret)
		{
			//TODO: see pcap_activate(3PCAP)
			switch (ret)
			{
				case PCAP_WARNING_PROMISC_NOTSUP:
					dcs::log_warn(DCS_LOGGING_AT, "Device does not support promiscuous mode");
					break;
#ifdef PCAP_WARNING_TSTAMP_TYPE_NOTSUP // Not available in old version of libpcap
				case PCAP_WARNING_TSTAMP_TYPE_NOTSUP:
					dcs::log_warn(DCS_LOGGING_AT, "Timestamp type isn't supported by the capture device");
					break;
#endif // PCAP_WARNING_TSTAMP_TYPE_NOTSUP
				case PCAP_WARNING:
					dcs::log_warn(DCS_LOGGING_AT, "Unclassified warning: " + ::std::string(pcap_geterr(this->native_handle())));
					break;
				case PCAP_ERROR_ACTIVATED:
					DCS_EXCEPTION_THROW(::std::logic_error, "The handle has been already activated");
					break;
				case PCAP_ERROR_NO_SUCH_DEVICE:
					DCS_EXCEPTION_THROW(::std::logic_error, "The capture device doesn't exist");
					break;
				case PCAP_ERROR_PERM_DENIED:
					DCS_EXCEPTION_THROW(::std::logic_error, "Not enough permission to open the capture source");
					break;
#ifdef PCAP_ERROR_PROMISC_PERM_DENIED // Not available in old version of libpcap
				case PCAP_ERROR_PROMISC_PERM_DENIED:
					DCS_EXCEPTION_THROW(::std::logic_error, "Not enough permission to put the capture source in promiscuous mode");
					break;
#endif // PCAP_ERROR_PROMISC_PERM_DENIED
				case PCAP_ERROR_RFMON_NOTSUP:
					DCS_EXCEPTION_THROW(::std::logic_error, "The capture device doesn't support monitor mode");
					break;
				case PCAP_ERROR_IFACE_NOT_UP:
					DCS_EXCEPTION_THROW(::std::logic_error, "The capture device isn't up");
					break;
				case PCAP_ERROR:
					DCS_EXCEPTION_THROW(::std::logic_error, "Unclassified error: " + ::std::string(pcap_geterr(this->native_handle())));
					break;
				default:
					break;
			}
		}

		active_ = true;
	}


	private: ::std::string dev_;
	private: bool active_;
}; // live_packet_sniffer

//class offline_packet_sniffer: public base_packet_sniffer
//{
//}; // offline_packet_sniffer
}}} // Namespace dcs::network::pcap

#endif // DCS_NETWORK_PCAP_PCAP_HPP
