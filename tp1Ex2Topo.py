from mininet.topo import Topo

class Ex1Topo(Topo):
    "Ex2 topology."

    def build(self):

        # Add hosts and switches
        switchL3 = self.addSwitch('sL3')


        switchL2_1 = self.addSwitch('s1')
        host1 = self.addHost('h1')
        host2 = self.addHost('h2')
        host3 = self.addHost('h3')
        
        switchL2_2 = self.addSwitch('s2')
        host4 = self.addHost('h4')
        host5 = self.addHost('h5')
        host6 = self.addHost('h6')
        
        switchL2_3 = self.addSwitch('s3')
        host7 = self.addHost('h7')
        host8 = self.addHost('h8')
        host9 = self.addHost('h9')
        
        # Add links
        self.addLink(switchL3, switchL2_1)
        self.addLink(switchL3, switchL2_2)
        self.addLink(switchL3, switchL2_3)
        
        self.addLink(switchL2_1, host1)
        self.addLink(switchL2_1, host2)
        self.addLink(switchL2_1, host3)
        
        self.addLink(switchL2_2, host4)
        self.addLink(switchL2_2, host5)
        self.addLink(switchL2_2, host6)
        
        self.addLink(switchL2_3, host7)
        self.addLink(switchL2_3, host8)
        self.addLink(switchL2_3, host9)
        
        
topos = {'ex1topo': (lambda: Ex1Topo())}
