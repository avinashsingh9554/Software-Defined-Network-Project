from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.node import Host
from mininet.node import OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info

from window_management import WindowManager  # Import WindowManager class
from packet_generator import PacketGenerator  # Import WindowManager class
from packet_arrival import PacketArrival



def myNetwork():

    net = Mininet( topo=None,
                   build=False,
                   ipBase='10.0.0.0/8')

    info( '*** Adding controller\n' )
    c0 = net.addController(name='c0',
                      controller=RemoteController,
                      protocol='tcp',
                      port=6633)

    info( '*** Add switches\n')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch, failMode='standalone')
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch, failMode='standalone')
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch, failMode='standalone')

    info( '*** Add hosts\n')
    h1 = net.addHost('h1', ip='10.0.0.1')
    h2 = net.addHost('h2', ip='10.0.0.2')
    h3 = net.addHost('h3', ip='10.0.0.3')
    h4 = net.addHost('h4', ip='10.0.0.4')

    info( '*** Add links\n')
    net.addLink(s1, h1, intfName1='s1-eth1', intfName2='h1-eth0')
    net.addLink(s1, h2, intfName1='s1-eth2', intfName2='h2-eth0')
    net.addLink(s2, h3, intfName1='s2-eth1', intfName2='h3-eth0')
    net.addLink(s2, h4, intfName1='s2-eth2', intfName2='h4-eth0')
    net.addLink(s1, s2, intfName1='s1-eth3', intfName2='s2-eth3')
    net.addLink(s2, s3, intfName1='s2-eth4', intfName2='s3-eth1')

    # Connect switches to controller
    net.addLink(s1, c0)
    net.addLink(s2, c0)
    net.addLink(s3, c0)

    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('s1').start([])
    net.get('s2').start([])
    net.get('s3').start([])

    info('*** Starting packet generator\n')
    # Create packet generator instance (details in packet_generator.py)
    packet_generator = PacketGenerator(net)
    packet_generator.start_generating_packets()
  
    info( '*** Post configure switches and hosts\n')
     
     
    # Open Mininet CLI for testing
    CLI(net)

    # Stop the network
    net.stop()

setLogLevel('info')
myNetwork()

