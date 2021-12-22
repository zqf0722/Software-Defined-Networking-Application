package edu.nyu.cs.sdn.apps.sps;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
/*
	Packets needed to match IP packets whose destination MAC is the MAC address assigned to host h
 */
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMatchField;
import org.openflow.protocol.OFOXMFieldType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import org.openflow.protocol.instruction.OFInstructionType;

import edu.nyu.cs.sdn.apps.util.Host;
import edu.nyu.cs.sdn.apps.util.SwitchCommands;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceListener;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryListener;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.routing.Link;
import net.floodlightcontroller.packet.Ethernet;

public class ShortestPathSwitching implements IFloodlightModule, IOFSwitchListener, 
		ILinkDiscoveryListener, IDeviceListener, InterfaceShortestPathSwitching
{
	public static final String MODULE_NAME = ShortestPathSwitching.class.getSimpleName();
	
	// Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);
    
    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;

    // Interface to link discovery service
    private ILinkDiscoveryService linkDiscProv;

    // Interface to device manager service
    private IDeviceService deviceProv;
    
    // Switch table in which rules should be installed
    public static byte table;
    
    // Map of hosts to devices
    private Map<IDevice,Host> knownHosts;

	// Map that stores the predecessor of a switch along the shortest path from the key to that switch
	private HashMap<IOFSwitch, HashMap<IOFSwitch, IOFSwitch>> paths;

	/**
     * Loads dependencies and initializes data structures.
     */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Initializing %s...", MODULE_NAME));
		Map<String,String> config = context.getConfigParams(this);
        table = Byte.parseByte(config.get("table"));
        
		this.floodlightProv = context.getServiceImpl(
				IFloodlightProviderService.class);
        this.linkDiscProv = context.getServiceImpl(ILinkDiscoveryService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
        
        this.knownHosts = new ConcurrentHashMap<IDevice,Host>();
        
        /*********************************************************************/
        /* TODO: Initialize other class variables, if necessary              */
		this.paths = new HashMap<IOFSwitch, HashMap<IOFSwitch, IOFSwitch>>();
        
        /*********************************************************************/
	}


	/*************************************************************************/
	/*
		Code added by myself.
		Computing the shortest paths from each switch to all other switches using
		Bellman-Ford's algorithm. The results will be assigned to this.paths whose form is like

			{switch1 : {switch1 : null, switch2 : switch4, ...},
			switch2 : {switch1: switch3, switch2 : null, ...},
			...}

		The i_th inner hash map stores the predecessor switch for each switch along the shortest path
		from switch i to all other switches.

		We assume that the cost of each link is 1.
	*/
	public HashMap<IOFSwitch, HashMap<IOFSwitch, IOFSwitch>> bfShortestPath() {

		Collection<IOFSwitch> switches = getSwitches().values();
		HashMap<IOFSwitch, HashMap<IOFSwitch, IOFSwitch>> shortestPaths = new HashMap<IOFSwitch, HashMap<IOFSwitch, IOFSwitch>>();

		for(IOFSwitch v : switches) {
			// Compute the shortest path for each of switch
			// Initialize distances, predecessors switch for all switches.
			HashMap<IOFSwitch, Integer> d = new HashMap<IOFSwitch, Integer>();
			HashMap<IOFSwitch, IOFSwitch> predecessor = new HashMap<IOFSwitch, IOFSwitch>();

			// Step1: Initialize graph
			for(IOFSwitch x : switches) {
				d.put(x, Integer.MAX_VALUE - 1);
				predecessor.put(x, null);
			}

			d.put(v, 0);
			// Step2: relax edges repeatedly
			for(int i=0;i<switches.size()-1;i++){
				for(Link link : getLinks()) {
					IOFSwitch source = getSwitches().get(link.getSrc());
					IOFSwitch dest = getSwitches().get(link.getDst());

					if(d.get(source) +1 < d.get(dest)) {
						d.put(dest, d.get(source)+1);
						predecessor.put(dest, source);
					}else if(d.get(dest) +1 < d.get(source)){
						d.put(source, d.get(dest)+1);
						predecessor.put(source, dest);
					}
				}
			}

			// No need to check for negative-weight cycles since the weight of all links are 1
			shortestPaths.put(v, predecessor);
		}

		return shortestPaths;
	}
	/********************************************************************/


	/********************************************************************/
	/* This log function which outputs the current shortestPaths hashmap is adopted from:
	 https://github.com/Randalthor95/ShortestPath. Make modifications to print my own maps. */
	private void logData() {
		StringBuilder message = new StringBuilder();
		message.append("\n##################### LOG DATA #######################################");
		message.append(getShortestPathsAsString(this.paths));
		log.info(message.toString());
	}


	private String getShortestPathsAsString(HashMap<IOFSwitch, HashMap<IOFSwitch, IOFSwitch>> shortestPaths) {
		StringBuilder message = new StringBuilder();
		message.append("\n#############ShortestPaths#############\n");

		for (Map.Entry<IOFSwitch, HashMap<IOFSwitch, IOFSwitch>> inner : shortestPaths.entrySet()) {
			Iterator<Map.Entry<IOFSwitch, IOFSwitch>> iterator2 = inner.getValue().entrySet().iterator();
			message.append(inner.getKey().getStringId()).append(": {");
			message.append("\n");
			while (iterator2.hasNext()) {
				Map.Entry<IOFSwitch, IOFSwitch> inner2 = iterator2.next();
				message.append("{ ");
				if (inner2.getKey() != null && inner2.getKey().getStringId() != null) {
					message.append(inner2.getKey().getStringId());
				} else {
					message.append("null");
				}
				message.append(" : ");
				if (inner2.getValue() != null) {
					message.append(inner2.getValue().getStringId());
				} else {
					message.append("null");
				}
				message.append(", ");
				message.append("}\n");
			}
			message.append("}\n");
		}
		return message.toString();
	}
	/********************************************************************/


	/**
     * Subscribes to events and performs other startup tasks.
     */
	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Starting %s...", MODULE_NAME));
		this.floodlightProv.addOFSwitchListener(this);
		this.linkDiscProv.addListener(this);
		this.deviceProv.addListener(this);
		
		/*********************************************************************/
		/* TODO: Perform other tasks, if necessary                           */
		// Initialize the shortest paths hash map here.
		this.paths = bfShortestPath();
		/*********************************************************************/
	}
	
	/**
	 * Get the table in which this application installs rules.
	 */
	public byte getTable()
	{ return table; }
	
    /**
     * Get a list of all known hosts in the network.
     */
    private Collection<Host> getHosts()
    { return this.knownHosts.values(); }
	
    /**
     * Get a map of all active switches in the network. Switch DPID is used as
     * the key.
     */
	private Map<Long, IOFSwitch> getSwitches()
    { return floodlightProv.getAllSwitchMap(); }
	
    /**
     * Get a list of all active links in the network.
     */
    private Collection<Link> getLinks()
    { return linkDiscProv.getLinks().keySet(); }


	/****************************************************************/
	/*
		Code written by myself.
		Set flow tables in each switch with rules to forward packets
		to host.
	*/
	public void setFlow(Host host) {

		if(host.isAttachedToSwitch()) {

			IOFSwitch hostS = host.getSwitch();
			OFMatch ofm = new OFMatch();
			ArrayList<OFMatchField> listofField = new ArrayList<OFMatchField>();

			OFMatchField e_type = new OFMatchField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_IPv4);
			OFMatchField mac = new OFMatchField(OFOXMFieldType.ETH_DST, Ethernet.toByteArray(host.getMACAddress()));
			listofField.add(e_type);
			listofField.add(mac);
			ofm.setMatchFields(listofField);

			for(IOFSwitch s : getSwitches().values()) {

				OFActionOutput ofaOutput = new OFActionOutput();

				// If the current host is the target host
				// We just set output port as the host's port
				if(s.getId() == hostS.getId()) {
					ofaOutput.setPort(host.getPort());
				// Else the source switch is not host switch, find the next switch's port and set it as the output port
				} else {
					// retrieve next switch on the path from s to hostS
					if(this.paths.containsKey(hostS)&&this.paths.get(hostS).containsKey(s)) {
						IOFSwitch pre = this.paths.get(hostS).get(s);
						for (Link link : getLinks()) {
							if ((pre.getId() == link.getDst()) && (s.getId() == link.getSrc())) {
								ofaOutput.setPort(link.getSrcPort());
							}
						}
					}
				}

				ArrayList<OFAction> listofAction = new ArrayList<OFAction>();
				ArrayList<OFInstruction> listofInstruction = new ArrayList<OFInstruction>();

				// subtype, good to add
				listofAction.add(ofaOutput);
				listofInstruction.add(new OFInstructionApplyActions(listofAction));

				// install the rules
				// No time out, default priority
				SwitchCommands.installRule(s, table, SwitchCommands.DEFAULT_PRIORITY, ofm, listofInstruction,
						SwitchCommands.NO_TIMEOUT, SwitchCommands.NO_TIMEOUT);
			}
		}
	}


	//	Set flow tables for each host
	public void buildFlowTables() {
		for(Host host : getHosts()) {
			setFlow(host);
		}
	}


	// Similarly, we write a function to delete a flow table and a function delete flow tables for all hosts.

	public void deleteFlow(Host host) {
		OFMatch ofm = new OFMatch();
		ArrayList<OFMatchField> listofField = new ArrayList<OFMatchField>();

		OFMatchField e_type = new OFMatchField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_IPv4);
		OFMatchField mac_dst = new OFMatchField(OFOXMFieldType.ETH_DST, Ethernet.toByteArray(host.getMACAddress()));
		OFMatchField mac_src = new OFMatchField(OFOXMFieldType.ETH_SRC, Ethernet.toByteArray(host.getMACAddress()));
		listofField.add(e_type);
		listofField.add(mac_dst);
		listofField.add(mac_src);
		ofm.setMatchFields(listofField);

		for(IOFSwitch s : getSwitches().values()) {
			SwitchCommands.removeRules(s, table, ofm);
		}
	}

	//	Delete flow tables for each host
	public void deleteFlowTables() {
		for(Host host : getHosts()) {
			deleteFlow(host);
		}
	}
	/**************************************************************************************/


    /**
     * Event handler called when a host joins the network.
     * @param device information about the host
     */
	@Override
	public void deviceAdded(IDevice device) 
	{
		Host host = new Host(device, this.floodlightProv);
		// We only care about a new host if we know its IP
		if (host.getIPv4Address() != null)
		{
			log.info(String.format("Host %s added", host.getName()));
			this.knownHosts.put(device, host);
			
			/*****************************************************************/
			/* TODO: Update routing: add rules to route to new host          */
			buildFlowTables();
			// Print the shortest path to the logs.
			// logData();
			/*****************************************************************/
		}
	}

	/**
     * Event handler called when a host is no longer attached to a switch.
     * @param device information about the host
     */
	@Override
	public void deviceRemoved(IDevice device) 
	{
		Host host = this.knownHosts.get(device);
		if (null == host)
		{
			host = new Host(device, this.floodlightProv);
			this.knownHosts.put(device, host);
		}
		
		log.info(String.format("Host %s is no longer attached to a switch", 
				host.getName()));
		
		/*********************************************************************/
		/* TODO: Update routing: remove rules to route to host               */
		deleteFlow(host);
		/*********************************************************************/
	}

	/**
     * Event handler called when a host moves within the network.
     * @param device information about the host
     */
	@Override
	public void deviceMoved(IDevice device) 
	{
		Host host = this.knownHosts.get(device);
		if (null == host)
		{
			host = new Host(device, this.floodlightProv);
			this.knownHosts.put(device, host);
		}
		
		if (!host.isAttachedToSwitch())
		{
			this.deviceRemoved(device);
			return;
		}
		log.info(String.format("Host %s moved to s%d:%d", host.getName(),
				host.getSwitch().getId(), host.getPort()));
		
		/*********************************************************************/
		/* TODO: Update routing: change rules to route to host               */
		deleteFlow(host);
		buildFlowTables();
		/*********************************************************************/
	}
	
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
		/* TODO: Update routing: change routing rules for all hosts          */
		// I choose to update all the routing rules affected or not by the change.
		deleteFlowTables();
		this.paths = bfShortestPath();
		buildFlowTables();
		// Print the shortest path to the logs.
		// logData();
		/*********************************************************************/
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * @param DPID for the switch
	 */
	@Override
	public void switchRemoved(long switchId) 
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d removed", switchId));
		
		/*********************************************************************/
		/* TODO: Update routing: change routing rules for all hosts          */
		// I choose to update all the routing rules affected or not by the change.
		deleteFlowTables();
		this.paths = bfShortestPath();
		buildFlowTables();
		// Print the shortest path to the logs.
		// logData();
		/*********************************************************************/
	}

	/**
	 * Event handler called when multiple links go up or down.
	 * @param updateList information about the change in each link's state
	 */
	@Override
	public void linkDiscoveryUpdate(List<LDUpdate> updateList) 
	{
		for (LDUpdate update : updateList)
		{
			// If we only know the switch & port for one end of the link, then
			// the link must be from a switch to a host
			if (0 == update.getDst())
			{
				log.info(String.format("Link s%s:%d -> host updated", 
					update.getSrc(), update.getSrcPort()));
			}
			// Otherwise, the link is between two switches
			else
			{
				log.info(String.format("Link s%s:%d -> %s:%d updated", 
					update.getSrc(), update.getSrcPort(),
					update.getDst(), update.getDstPort()));
			}
		}
		
		/*********************************************************************/
		/* TODO: Update routing: change routing rules for all hosts          */
		this.paths = bfShortestPath();
		buildFlowTables();
		// Print the shortest path to the logs.
		// logData();
		/*********************************************************************/
	}

	/**
	 * Event handler called when link goes up or down.
	 * @param update information about the change in link state
	 */
	@Override
	public void linkDiscoveryUpdate(LDUpdate update) 
	{ this.linkDiscoveryUpdate(Arrays.asList(update)); }
	
	/**
     * Event handler called when the IP address of a host changes.
     * @param device information about the host
     */
	@Override
	public void deviceIPV4AddrChanged(IDevice device) 
	{ this.deviceAdded(device); }

	/**
     * Event handler called when the VLAN of a host changes.
     * @param device information about the host
     */
	@Override
	public void deviceVlanChanged(IDevice device) 
	{ /* Nothing we need to do, since we're not using VLANs */ }
	
	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param DPID for the switch
	 */
	@Override
	public void switchActivated(long switchId) 
	{ /* Nothing we need to do, since we're not switching controller roles */ }

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param DPID for the switch
	 */
	@Override
	public void switchChanged(long switchId) 
	{ /* Nothing we need to do */ }
	
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
	{ /* Nothing we need to do, since we'll get a linkDiscoveryUpdate event */ }

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
	public String getName() 
	{ return this.MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(String type, String name) 
	{ return false; }

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(String type, String name) 
	{ return false; }
	
    /**
     * Tell the module system which services we provide.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() 
	{
		Collection<Class<? extends IFloodlightService>> services =
					new ArrayList<Class<? extends IFloodlightService>>();
		services.add(InterfaceShortestPathSwitching.class);
		return services; 
	}

	/**
     * Tell the module system which services we implement.
     */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> 
			getServiceImpls() 
	{ 
        Map<Class<? extends IFloodlightService>, IFloodlightService> services =
        			new HashMap<Class<? extends IFloodlightService>, 
        					IFloodlightService>();
        // We are the class that implements the service
        services.put(InterfaceShortestPathSwitching.class, this);
        return services;
	}

	/**
     * Tell the module system which modules we depend on.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> 
			getModuleDependencies() 
	{
		Collection<Class<? extends IFloodlightService >> modules =
	            new ArrayList<Class<? extends IFloodlightService>>();
		modules.add(IFloodlightProviderService.class);
		modules.add(ILinkDiscoveryService.class);
		modules.add(IDeviceService.class);
        return modules;
	}
}
