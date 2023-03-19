ICMP_REQUEST = 8
ICMP_REPLY   = 0

ARP_REQUEST  = 1
ARP_REPLY    = 0

ARP  = '0x806'
IPV4 = '0x800'
UDP  = '0x11'
TCP  = '0x6'
ICMP = '0x1'


ETHERNET_PATTERN  = '!6s6sH'
IPV4_PATTERN      = '!8xBB2x4s4s'
TCP_PATTERN       = '!HHLLH'
ICMP_PATTERN      = '!BBHHH'
UDP_PATTERN       = '!HHHH'
ARP_PATTERN       = '!HHBBH6s4s6s4s'

# CONSTANTS
ALL_PACKETS          = 3
BUFFER_SIZE          = 65535
WINDOW_SIZE          = (1400, 950)
OUTPUT_SCREEN_SIZE   = (900, 950)
TOOLBAR_FONT         = ('Courier New', 16, 'bold')
OUTPUT_SCREEN_FONT   = ('Courier New', 20)
APP_THEME            = 'Default 1'

# Hystogram
BAR_WIDTH       = 70
BAR_SPACING     = 80
EDGE_OFFSET     = 210
HYSTO_SIZE      = (600,100)
DATA_SIZE       = (530,100)
COLORS          = ['blue','red','green', 'magenta']

# Trend
STEP_SIZE       = 1  
SAMPLES         = 100 
SAMPLE_MAX      = 100 
CANVAS_SIZE     = (650, 100)

HELLO_MESSAGE = """ 
            ---------------------------------------------------------------
             ____            _        _     ____        _  __  __           
            |  _ \ __ _  ___| | _____| |_  / ___| _ __ (_)/ _|/ _| ___ _ __ 
            | |_) / _` |/ __| |/ / _ \ __| \___ \| '_ \| | |_| |_ / _ \ '__|
            |  __/ (_| | (__|   <  __/ |_   ___) | | | | |  _|  _|  __/ |   
            |_|   \__,_|\___|_|\_\___|\__| |____/|_| |_|_|_| |_|  \___|_|   
            ---------------------------------------------------------------

                        by Bluewhale, Giorgio Daniele, 2023                                                          
"""