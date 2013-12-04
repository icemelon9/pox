"""
Author Haichen Shen
"""

from pox.core import core
from pox.openflow import FlowRemoved
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr, str_to_bool
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.packet.udp import udp
from pox.lib.packet.dns import dns
from pox.lib.addresses import IPAddr, EthAddr

from LearningSwitch import LearningSwitch

log = core.getLogger()

IDLE_TIMEOUT = 10
HARD_TIMEOUT = 30

def ip_to_str():
	pass

class NAT (EventMixin):

	def __init__(self, connection):
		self.flowToPort = {}
		self.connection = connection
		self.listenTo(connection)
		#print 'nat'
		#print connection._eventMixin_events
		#self.addListener(FlowRemoved, getattr(self, '_handle_FlowRemoved'))

	def _handle_PacketIn(self, event):
		
		# parsing the input packet
		packet = event.parse()

		if (event.port == 4):
			log.info("get a packet from port 4, forward to port 1")

		if packet.type == packet.LLDP_TYPE or packet.type == 0x86DD:
			# Drop LLDP packets
			# Drop IPv6 packets
			# send of command without actions

			msg = of.ofp_packet_out()
			msg.buffer_id = event.ofp.buffer_id
			msg.in_port = event.port
			self.connection.send(msg)
			return

		elif packet.type == ethernet.IP_TYPE: 
			ip_packet = packet.next
			if ip_packet.protocol != ipv4.TCP_PROTOCOL:
				log.info("not tcp packet, drop it")
				return
			tcp_packet = ip_packet.next
			log.info("in-port %s" % event.port)
			if (event.port == 4):
				log.info("get a packet from port 4, forward to port 1")
				msg = of.ofp_flow_mod()
				#msg.match.nw_src = ip_packet.srcip
				#msg.match = of.ofp_match.from_packet(ip_packet)
				msg.match.dl_src = packet.src
				msg.match.dl_type = packet.type
				msg.match.nw_dst = ip_packet.dstip
				msg.match.nw_proto = ip_packet.protocol

				msg.flags = of.ofp_flow_mod_flags_rev_map['OFPFF_SEND_FLOW_REM']
				msg.idle_timeout = IDLE_TIMEOUT
				msg.hard_timeout = HARD_TIMEOUT
				action = of.ofp_action_tp_port.set_dst(self.from_port)
				msg.actions.append(action)
				action = of.ofp_action_nw_addr.set_dst(IPAddr("10.0.1.101"))
				msg.actions.append(action)
				action = of.ofp_action_dl_addr.set_dst(EthAddr("0:0:0:0:0:1"))
				msg.actions.append(action)
				msg.actions.append(of.ofp_action_output(port = 1))
				msg.buffer_id = event.ofp.buffer_id
				self.connection.send(msg)
			else:
				log.info("get a packet from port 1, forward to port 4, origin tcp port: %s" % tcp_packet.srcport)
				self.from_port = tcp_packet.srcport

				msg = of.ofp_flow_mod()
				msg.match.dl_src = packet.src
				msg.match.dl_type = packet.type
				msg.match.nw_src = ip_packet.srcip
				msg.match.nw_proto = ip_packet.protocol

				msg.flags = of.ofp_flow_mod_flags_rev_map['OFPFF_SEND_FLOW_REM']
				msg.idle_timeout = IDLE_TIMEOUT
				msg.hard_timeout = HARD_TIMEOUT

				action = of.ofp_action_tp_port.set_src(8888)
				msg.actions.append(action)
				action = of.ofp_action_nw_addr.set_src(IPAddr("172.64.3.1"))
				msg.actions.append(action)
				action = of.ofp_action_dl_addr.set_dst(EthAddr("0:0:0:0:0:4"))
				msg.actions.append(action)
				msg.actions.append(of.ofp_action_output(port = 4))
				msg.buffer_id = event.ofp.buffer_id
				self.connection.send(msg)

				"""msg = of.ofp_packet_out()
				msg.buffer_id = event.ofp.buffer_id
				
				action = of.ofp_action_nw_addr.set_dst(IPAddr("172.64.3.1"))
				log.info("change ip addr to %s" % action.nw_addr)
				msg.actions.append(action)
				msg.actions.append(of.ofp_action_output(port = 4))
				msg.in_port = event.port
				self.connection.send(msg)"""
				#new_pkt = 


			src_ip = ip_packet.srcip
			"""if ip_packet.protocol == ipv4.TCP_PROTOCOL:
				tcp_packet = ip_packet.payload
				src_port = tcp_packet.srcport

				log.info('receive tcp packet from %s:%s' % (src_ip, src_port))"""

	def _handle_FlowRemoved(self, event):
		log.info('Flow removed event 2')
		log.info(event.timeout)
		log.info(event.idleTimeout)
		log.info(event.hardTimeout)


class controller (EventMixin):

	def __init__(self):
		self.listenTo(core.openflow)
		#print core.openflow._eventMixin_events

	def _handle_ConnectionUp(self, event):
		log.debug("Connection %s" % (event.connection))
		if (event.dpid == 1):
			log.info("Creating learning switch %s" % dpidToStr(event.dpid))
			LearningSwitch(event.connection)
		else:
			log.info("Creating NAT %s" % dpidToStr(event.dpid))
			#LearningSwitch(event.connection)
			NAT(event.connection)

def launch():
	core.registerNew(controller)