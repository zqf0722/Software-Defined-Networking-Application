package edu.nyu.cs.sdn.apps.loadbalancer;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import edu.nyu.cs.sdn.apps.util.SwitchCommands;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFType;
import org.openflow.protocol.OFMatchField;
import org.openflow.protocol.OFOXMFieldType;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.action.OFActionSetField;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import org.openflow.protocol.instruction.OFInstructionGotoTable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.nyu.cs.sdn.apps.util.ArpServer;
import edu.nyu.cs.sdn.apps.util.Host;
// Import the l3routing rules. Noticed that our l3routing tables are saved in InterfaceShortestPathSwitching file
// Instead of IL3Routing, so the structure of this program should be changed.
import edu.nyu.cs.sdn.apps.sps.ShortestPathSwitching;
import edu.nyu.cs.sdn.apps.sps.InterfaceShortestPathSwitching;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.internal.DeviceManagerImpl;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.util.MACAddress;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;

public class LoadBalancer implements IFloodlightModule, IOFSwitchListener,
		IOFMessageListener
{
	public static final String MODULE_NAME = LoadBalancer.class.getSimpleName();
	
	private static final byte TCP_FLAG_SYN = 0x02;
	
	private static final short IDLE_TIMEOUT = 20;
	
	// Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);
    
    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;
    
    // Interface to device manager service
    private IDeviceService deviceProv;
    
    // Interface to L3Routing application
    private InterfaceShortestPathSwitching l3RoutingApp;
    
    // Switch table in which rules should be installed
    private byte table;
    
    // Set of virtual IPs and the load balancer instances they correspond with
    private Map<Integer,LoadBalancerInstance> instances;

    /**
     * Loads dependencies and initializes data structures.
     */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Initializing %s...", MODULE_NAME));
		
		// Obtain table number from config
		Map<String,String> config = context.getConfigParams(this);
        this.table = Byte.parseByte(config.get("table"));
        
        // Create instances from config
        this.instances = new HashMap<Integer,LoadBalancerInstance>();
        String[] instanceConfigs = config.get("instances").split(";");
        for (String instanceConfig : instanceConfigs)
        {
        	String[] configItems = instanceConfig.split(" ");
        	if (configItems.length != 3)
        	{ 
        		log.error("Ignoring bad instance config: " + instanceConfig);
        		continue;
        	}
        	LoadBalancerInstance instance = new LoadBalancerInstance(
        			configItems[0], configItems[1], configItems[2].split(","));
            this.instances.put(instance.getVirtualIP(), instance);
            log.info("Added load balancer instance: " + instance);
        }
        
		this.floodlightProv = context.getServiceImpl(IFloodlightProviderService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
        this.l3RoutingApp = context.getServiceImpl(InterfaceShortestPathSwitching.class);
        
        /*********************************************************************/
        /* TODO: Initialize other class variables, if necessary              */
        
        /*********************************************************************/
	}

	/**
     * Subscribes to events and performs other startup tasks.
     */
	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Starting %s...", MODULE_NAME));
		this.floodlightProv.addOFSwitchListener(this);
		this.floodlightProv.addOFMessageListener(OFType.PACKET_IN, this);
		
		/*********************************************************************/
		/* TODO: Perform other tasks, if necessary                           */
		
		/*********************************************************************/
	}

	/*************************************************************************/
	/*
	Code written by myself. When adjusting the code structure and checking I reference to
	the project at https://github.com/vnatesh/SDN-Controller.
	Function that sends ip and arp packets. Use flag to distinguish ip packets from
	arp packets and function that sends all other packets.
	Packets match functions act like the one in ShortestPathSwitching
	 */
	public void addSwitchRules(IOFSwitch sw, String flag){
		for(int vh:this.instances.keySet()){
			OFMatch ofm = new OFMatch();
			ArrayList<OFMatchField> listofField = new ArrayList<OFMatchField>();
			OFMatchField e_type;
			OFMatchField match;
			if(flag.equals("ip")){
				// ipv4 type, packets' destination is virtual host
				log.info("IP switch rules added");
				e_type = new OFMatchField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_IPv4);
				match = new OFMatchField(OFOXMFieldType.IPV4_DST, vh);
			}else if(flag.equals("arp")){
				// arp type, target is virtual host
				log.info("ARP switch rules added");
				e_type = new OFMatchField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_ARP);
				match = new OFMatchField(OFOXMFieldType.ARP_TPA, vh);
			}else{
				log.info("Wrong packet type");
				return;
			}
			listofField.add(e_type);
			listofField.add(match);
			ofm.setMatchFields(listofField);

			// Create action list
			OFActionOutput ofaOutput = new OFActionOutput();
			ofaOutput.setPort(OFPort.OFPP_CONTROLLER);
			ArrayList<OFAction> listofAction = new ArrayList<OFAction>();
			listofAction.add(ofaOutput);

			// Create instruction list
			OFInstructionApplyActions acts = new OFInstructionApplyActions(listofAction);
			ArrayList<OFInstruction> listofInstruction = new ArrayList<OFInstruction>();
			listofInstruction.add(acts);
			// No time out. Higher priority than other rules.
			SwitchCommands.installRule(sw, this.table, SwitchCommands.DEFAULT_PRIORITY,
					ofm, listofInstruction);
		}
	}


	public void addOther(IOFSwitch sw){
		log.info("Other switch rules added.");
		OFMatch ofm = new OFMatch();
		OFInstructionGotoTable instructionTable = new OFInstructionGotoTable();
		instructionTable.setTableId(ShortestPathSwitching.table);
		ArrayList<OFInstruction> listofInstruction = new ArrayList<OFInstruction>();
		// All other rules should have lower priority.
		listofInstruction.add(instructionTable);
		SwitchCommands.installRule(sw, this.table, (short)(SwitchCommands.DEFAULT_PRIORITY-1), ofm, listofInstruction);
	}
	/*************************************************************************/


	/**
     * Event handler called when a switch joins the network.
     * @param DPID for the switch
     */
	@Override
	public void switchAdded(long switchId) 
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d added", switchId));
		
		/*********************************************************************/
		/* TODO: Install rules to send:                                      */
		/*       (1) packets from new connections to each virtual load       */
		/*       balancer IP to the controller                               */
		/*       (2) ARP packets to the controller, and                      */
		/*       (3) all other packets to the next rule table in the switch  */
		// ip packets
		addSwitchRules(sw, "ip");
		// arp packets
		addSwitchRules(sw, "arp");
		// others
		addOther(sw);
		/*********************************************************************/
	}

	/*******************************************************************/
	/*
	Code written by myself.
	arpReply(Ethernet ethPkt, OFPacketIn pktIn, IOFSwitch sw) sends arp reply
	rewrite(Ethernet ethPkt, OFPacketIn pktIn, IOFSwitch sw) for TCP SYNs rewrite
	for other TCP, TCP reset.
	 */
	public void arpReply(Ethernet ethPkt, OFPacketIn pktIn, IOFSwitch sw){


		// get the arp packets in the payload
		ARP arpPkt = (ARP) ethPkt.getPayload();
		// virtual host ip address
		int virtualIP = IPv4.toIPv4Address(arpPkt.getTargetProtocolAddress());
		// if flag is true then the hostIP is valid else just return.
		boolean flag = false;
		for(int validIP:instances.keySet()){
			if(validIP==virtualIP){
				flag = true;
				break;
			}
		}
		// According to the ARP class, the getOpCode() method get the opcode of this packet
		// ARP.OP_REQUEST is a public variable which means it's an arp request packet.
		// Reply to the request packet, and ignore others.
		if(flag&&(arpPkt.getOpCode() == ARP.OP_REQUEST)) {
			// Use the class method to get the MAC address of the virtual host
			byte[] vhmac = instances.get(virtualIP).getVirtualMAC();
			log.info("Arp reply process!");
			// Set the arp reply packet
			// Similar to the ArpServer, just the sender is the virtual host.
			arpPkt.setOpCode(ARP.OP_REPLY);
			arpPkt.setTargetHardwareAddress(arpPkt.getSenderHardwareAddress());
			arpPkt.setTargetProtocolAddress(arpPkt.getSenderProtocolAddress());
			arpPkt.setSenderHardwareAddress(vhmac);
			arpPkt.setSenderProtocolAddress(virtualIP);
			// Set the Ethernet packet content.
			// Ethernet content.
			ethPkt.setDestinationMACAddress(ethPkt.getSourceMACAddress());
			ethPkt.setSourceMACAddress(vhmac);
			// Output the reply packet information to the log
			log.info("Arp reply packet sending: "+arpPkt.toString());
			// Send the packet
			SwitchCommands.sendPacket(sw, (short) pktIn.getInPort(), ethPkt);
		}
	}

	public void rewrite(Ethernet ethPkt, OFPacketIn pktIn, IOFSwitch sw){
		// Only TCP packets will use this function.
		IPv4 ipPkt = (IPv4) ethPkt.getPayload();
		// If not TCP return;
		if(ipPkt.getProtocol() != IPv4.PROTOCOL_TCP) return;
		// Similarly, get the TCP payload in IP datagram.
		TCP tcpPkt = (TCP) ipPkt.getPayload();
		int virtualIP = ipPkt.getDestinationAddress();
		if(tcpPkt.getFlags() == TCP_FLAG_SYN){
			// TCP SYNs
			log.info("TCP SYNs rewriting.");
			int srcIP = ipPkt.getSourceAddress();

			boolean flag = false;
			for(int validIP:instances.keySet()){
				if(validIP==virtualIP){
					flag = true;
					break;
				}
			}
			// Not valid virtual IP address.
			if(!flag) return;

			int srcPort = tcpPkt.getSourcePort();
			int dstPort = tcpPkt.getDestinationPort();

			// Find the next host's IP and MAC balanced by the virtual IP
			int hostIP = instances.get(virtualIP).getNextHostIP();
			byte[] hostMac = getHostMACAddress(hostIP);

			log.info(String.format("Rewriting the IP address to %s, rewriting the MAC address to %s"
					, IPv4.fromIPv4Address(hostIP), MACAddress.valueOf(hostMac).toString()));

			// Variable needed to construct the rules.
			OFMatch ofm;
			ArrayList<OFMatchField> listofIPField;
			ArrayList<OFAction> listofAction;
			ArrayList<OFInstruction> listofInstructon;

			for(int i=0;i<2;i++){
				// We do it 2 times, one for rewriting the destination IP and MAC sent from a client to virtual ip.
				// Another for rewriting the source IP and MAC sent from server to client.

				// Basic IP packet field
				listofIPField = new ArrayList<OFMatchField>();
				listofIPField.add(new OFMatchField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_IPv4));
				listofIPField.add(new OFMatchField(OFOXMFieldType.IPV4_SRC, srcIP));
				listofIPField.add(new OFMatchField(OFOXMFieldType.IPV4_DST, virtualIP));
				listofIPField.add(new OFMatchField(OFOXMFieldType.IP_PROTO, IPv4.PROTOCOL_TCP));

				if(i == 1){
					// client to virtual ip.
					listofIPField.add(new OFMatchField(OFOXMFieldType.TCP_SRC, srcPort));
					listofIPField.add(new OFMatchField(OFOXMFieldType.TCP_DST, dstPort));
					listofAction = new ArrayList<OFAction>();
					listofAction.add(new OFActionSetField(OFOXMFieldType.ETH_DST, hostMac));
					listofAction.add(new OFActionSetField(OFOXMFieldType.IPV4_DST, hostIP));
				}else{
					// Other direction
					listofIPField.add(new OFMatchField(OFOXMFieldType.TCP_SRC, dstPort));
					listofIPField.add(new OFMatchField(OFOXMFieldType.TCP_DST, srcPort));
					listofAction = new ArrayList<OFAction>();
					listofAction.add(new OFActionSetField(OFOXMFieldType.ETH_SRC, instances.get(virtualIP).getVirtualMAC()));
					listofAction.add(new OFActionSetField(OFOXMFieldType.IPV4_SRC, virtualIP));
				}
				// Install the rules separately. Standard for all field match.
				ofm = new OFMatch();
				ofm.setMatchFields(listofIPField);
				OFInstructionApplyActions actions = new OFInstructionApplyActions(listofAction);

				OFInstructionGotoTable ofInstructionGotoTable = new OFInstructionGotoTable();
				ofInstructionGotoTable.setTableId(ShortestPathSwitching.table);

				listofInstructon = new ArrayList<OFInstruction>();
				listofInstructon.add(actions);
				listofInstructon.add(ofInstructionGotoTable);
				// Gives connection-specific rules a higher priority, Idle timeout 20 seconds.
				SwitchCommands.installRule(sw, this.table, (short) (SwitchCommands.DEFAULT_PRIORITY + 1),
						ofm, listofInstructon, SwitchCommands.NO_TIMEOUT, (short)IDLE_TIMEOUT);
			}
		}else{
			// TCP reset, build TCP packet configuration, set flags to RST.
			log.info("TCP reset rewriting.");
			tcpPkt.setSourcePort(tcpPkt.getDestinationPort());
			tcpPkt.setDestinationPort(tcpPkt.getSourcePort());
			final byte TCP_FLAG_RST = 0x04;
			tcpPkt.setFlags((short) TCP_FLAG_RST);
			tcpPkt.setSequence(tcpPkt.getAcknowledge() );
			tcpPkt.setWindowSize((short) 0);
			tcpPkt.setChecksum((short) 0);
			tcpPkt.serialize();

			// Encapsulate TCP into IP datagrams.
			ipPkt.setPayload(tcpPkt);
			int destIp = ipPkt.getSourceAddress();
			int srcIp = ipPkt.getDestinationAddress();
			ipPkt.setDestinationAddress(destIp);
			ipPkt.setSourceAddress(srcIp);
			ipPkt.setChecksum((short) 0);
			ipPkt.serialize();

			// Encapsulate IP datagrams into Ethernet frames.
			ethPkt.setPayload(ipPkt);
			byte[] destMac = ethPkt.getSourceMACAddress();
			byte[] srcMac = ethPkt.getDestinationMACAddress();
			ethPkt.setDestinationMACAddress(destMac);
			ethPkt.setSourceMACAddress(srcMac);

			SwitchCommands.sendPacket(sw, (short) pktIn.getInPort(), ethPkt);
		}

	}
	/*******************************************************************/



	/**
	 * Handle incoming packets sent from switches.
	 * @param sw switch on which the packet was received
	 * @param msg message from the switch
	 * @param cntx the Floodlight context in which the message should be handled
	 * @return indication whether another module should also process the packet
	 */
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) 
	{
		// We're only interested in packet-in messages
		if (msg.getType() != OFType.PACKET_IN)
		{ return Command.CONTINUE; }
		OFPacketIn pktIn = (OFPacketIn)msg;
		
		// Handle the packet
		Ethernet ethPkt = new Ethernet();
		ethPkt.deserialize(pktIn.getPacketData(), 0,
				pktIn.getPacketData().length);
		
		/*********************************************************************/
		/* TODO: Send an ARP reply for ARP requests for virtual IPs; for TCP */
		/*       SYNs sent to a virtual IP, select a host and install        */
		/*       connection-specific rules to rewrite IP and MAC addresses;  */
		/*       for all other TCP packets sent to a virtual IP, send a TCP  */
		/*       reset; ignore all other packets                             */
		if(ethPkt.getEtherType() == Ethernet.TYPE_ARP){
			arpReply(ethPkt, pktIn, sw);
		}else if(ethPkt.getEtherType() == Ethernet.TYPE_IPv4){
			rewrite(ethPkt, pktIn, sw);
		}
		// Ignore other packets.
		/*********************************************************************/
		return Command.CONTINUE;
	}
	
	/**
	 * Returns the MAC address for a host, given the host's IP address.
	 * @param hostIPAddress the host's IP address
	 * @return the hosts's MAC address, null if unknown
	 */
	private byte[] getHostMACAddress(int hostIPAddress)
	{
		Iterator<? extends IDevice> iterator = this.deviceProv.queryDevices(
				null, null, hostIPAddress, null, null);
		if (!iterator.hasNext())
		{ return null; }
		IDevice device = iterator.next();
		return MACAddress.valueOf(device.getMACAddress()).toBytes();
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * @param DPID for the switch
	 */
	@Override
	public void switchRemoved(long switchId) 
	{ /* Nothing we need to do, since the switch is no longer active */ }

	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param DPID for the switch
	 */
	@Override
	public void switchActivated(long switchId)
	{ /* Nothing we need to do, since we're not switching controller roles */ }

	/**
	 * Event handler called when a port on a switch goes up or down, or is
	 * added or removed.
	 * @param DPID for the switch
	 * @param port the port on the switch whose status changed
	 * @param type the type of status change (up, down, add, remove)
	 */
	@Override
	public void switchPortChanged(long switchId, ImmutablePort port,
			PortChangeType type) 
	{ /* Nothing we need to do, since load balancer rules are port-agnostic */}

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param DPID for the switch
	 */
	@Override
	public void switchChanged(long switchId) 
	{ /* Nothing we need to do */ }
	
    /**
     * Tell the module system which services we provide.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() 
	{ return null; }

	/**
     * Tell the module system which services we implement.
     */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> 
			getServiceImpls() 
	{ return null; }

	/**
     * Tell the module system which modules we depend on.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> 
			getModuleDependencies() 
	{
		Collection<Class<? extends IFloodlightService >> floodlightService =
	            new ArrayList<Class<? extends IFloodlightService>>();
        floodlightService.add(IFloodlightProviderService.class);
        floodlightService.add(IDeviceService.class);
        return floodlightService;
	}

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
	public String getName() 
	{ return MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) 
	{
		return (OFType.PACKET_IN == type 
				&& (name.equals(ArpServer.MODULE_NAME) 
					|| name.equals(DeviceManagerImpl.MODULE_NAME))); 
	}

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) 
	{ return false; }
}
