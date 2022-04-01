from mininet.topo import Topo

class Ex1Topo( Topo ):
    "Ex2 topology."

    def build( self ):

        # Add hosts and switches
        switch = self.addSwitch( 's1' )
        firstHost = self.addHost( 'h1' )
        secondHost = self.addHost( 'h2' )
        thirdHost = self.addHost( 'h3' )
        fourthHost = self.addHost( 'h4' )
        
        # Add links
        self.addLink( switch, firstHost )
        self.addLink( switch, secondHost )
        self.addLink( switch, thirdHost )
        self.addLink( switch, fourthHost )

topos = { 'ex1topo': ( lambda: Ex1Topo() ) }
