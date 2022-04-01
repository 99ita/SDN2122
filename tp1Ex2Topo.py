from mininet.topo import Topo

class Ex2Topo(Topo):
    "Ex2 topology."

    def build(self):
        #Add hosts and switches
        switchL3 = self.addSwitch('sL3')


        switchL2_1 = self.addSwitch('sL2_1')
        host1 = self.addHost('h1',ip="10.0.1.1/24")
        host2 = self.addHost('h2',ip="10.0.1.2/24")
        host3 = self.addHost('h3',ip="10.0.1.3/24")
        
        switchL2_2 = self.addSwitch('sL2_2')
        host4 = self.addHost('h4',ip="10.0.2.1/24")
        host5 = self.addHost('h5',ip="10.0.2.2/24")
        host6 = self.addHost('h6',ip="10.0.2.3/24")
        
        switchL2_3 = self.addSwitch('sL2_3')
        host7 = self.addHost('h7',ip="10.0.3.1/24")
        host8 = self.addHost('h8',ip="10.0.3.2/24")
        host9 = self.addHost('h9',ip="10.0.3.3/24")
        
        #Add links
        self.addLink(switchL3, switchL2_1, delay='5ms')
        self.addLink(switchL3, switchL2_2)
        self.addLink(switchL3, switchL2_3)
        
        self.addLink(switchL2_1, host1)
        self.addLink(switchL2_1, host2)
        self.addLink(switchL2_1, host3)
        
        self.addLink(switchL2_2, host4)
        self.addLink(switchL2_2, host5)
        self.addLink(switchL2_2, host6, delay='5ms')
        
        self.addLink(switchL2_3, host7)
        self.addLink(switchL2_3, host8)
        self.addLink(switchL2_3, host9, loss=10)

      
        
topos = {'ex2topo': (lambda: Ex2Topo())}
