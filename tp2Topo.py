from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.cli import CLI



def build():
    net = Mininet(controller=RemoteController, switch=OVSSwitch)

    #Add hosts and switches
    switchL3_1 = net.addSwitch('sL3_1', dpid = '11')
    switchL2_1 = net.addSwitch('sL2_1', dpid = '1')
    host1 = net.addHost('h1',ip="10.0.1.1/24", defaultRoute='via 10.0.1.20')
    host2 = net.addHost('h2',ip="10.0.1.2/24", defaultRoute='via 10.0.1.20')
    host3 = net.addHost('h3',ip="10.0.1.3/24", defaultRoute='via 10.0.1.20')
    
    switchL3_2 = net.addSwitch('sL3_2', dpid = '12')
    switchL2_2 = net.addSwitch('sL2_2', dpid = '2')
    host4 = net.addHost('h4',ip="10.0.2.1/24", defaultRoute='via 10.0.2.20')
    host5 = net.addHost('h5',ip="10.0.2.2/24", defaultRoute='via 10.0.2.20')
    host6 = net.addHost('h6',ip="10.0.2.3/24", defaultRoute='via 10.0.2.20')
    
    switchL3_3 = net.addSwitch('sL3_3', dpid = '13')
    switchL2_3 = net.addSwitch('sL2_3', dpid = '3')
    host7 = net.addHost('h7',ip="10.0.3.1/24", defaultRoute='via 10.0.3.20')
    host8 = net.addHost('h8',ip="10.0.3.2/24", defaultRoute='via 10.0.3.20')
    host9 = net.addHost('h9',ip="10.0.3.3/24", defaultRoute='via 10.0.3.20')
    
    
    #Add links
    net.addLink(switchL3_1, switchL3_2)
    net.addLink(switchL3_2, switchL3_3)
    net.addLink(switchL3_3, switchL3_1, delay='5ms')
    
    net.addLink(switchL3_1, switchL2_1)
    net.addLink(switchL3_2, switchL2_2)
    net.addLink(switchL3_3, switchL2_3)
    
    net.addLink(switchL2_1, host1)
    net.addLink(switchL2_1, host2)
    net.addLink(switchL2_1, host3)
    
    net.addLink(switchL2_2, host4)
    net.addLink(switchL2_2, host5)
    net.addLink(switchL2_2, host6)
    
    net.addLink(switchL2_3, host7)
    net.addLink(switchL2_3, host8)
    net.addLink(switchL2_3, host9)

    cL2 = net.addController('cL2', controller=RemoteController, ip='127.0.0.1', port=6633, protocols='OpenFlow13')
    cL3 = net.addController('cL3', controller=RemoteController, ip='127.0.0.1', port=6653, protocols='OpenFlow13')
      

    net.build()

    cL2.start()
    cL3.start()
    switchL2_1.start([cL2])
    switchL2_2.start([cL2])
    switchL2_3.start([cL2])

    switchL3_1.start([cL3])
    switchL3_2.start([cL3])
    switchL3_3.start([cL3])
    
    CLI(net)
    net.stop()

if __name__ == '__main__':
    build()