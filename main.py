#GUI library importing
import PySimpleGUI as sg
#Socket library importing
import socket
#Parser library importing
from netparser import packetParser
# Thread library importing
from threading import Thread

# From Internet :)
class ParserThread(Thread):
    def __init__(self, group=None, target=None, name=None, args=(), kwargs={}, Verbose=None):
        Thread.__init__(self, group, target, name, args, kwargs)
        self._return = None
    def run(self):
        if self._target is not None:
            self._return = self._target(*self._args, **self._kwargs)
    def join(self, *args):
        Thread.join(self, *args)
        return self._return

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

# create an array of time and data value




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


def startSniffing():
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ALL_PACKETS))
    sock.setblocking(True)
    return sock


def main():

    startCapture = False
    socketOpened = False
    sniffOutput = ''
    nPacket     = 0

    sniffARP    = False
    sniffICMP   = False
    sniffTCP    = False
    sniffUDP    = False

    protocolCounters = [0,0,0,0]

    relARP  = 0
    relICMP = 0
    relTCP  = 0
    relUDP  = 0

    # Defining a theme
    sg.theme(APP_THEME)

    hystogram = sg.Graph(HYSTO_SIZE, (0,0), DATA_SIZE, background_color = 'black')
    curves    = sg.Graph(CANVAS_SIZE, (0,0), (SAMPLES, SAMPLE_MAX), background_color = 'black', key = 'trend')




    layout = [
        [
        sg.Button('Start', key = 'Start', font = TOOLBAR_FONT, disabled = False),
        sg.Button('Stop', key = 'Stop',  font = TOOLBAR_FONT, disabled = True),
        sg.Button('Continue',  key = 'Continue',  font = TOOLBAR_FONT, disabled = True),
        sg.Checkbox('ARP', text_color = 'blue', key = 'ARP', default = False, font = TOOLBAR_FONT),
        sg.Checkbox('ICMP', text_color = 'magenta', key = 'ICMP', default = False, font = TOOLBAR_FONT),
        sg.Checkbox('TCP', text_color = 'red', key = 'TCP', default = False, font = TOOLBAR_FONT),
        sg.Checkbox('UDP', text_color = 'green', key = 'UDP', default = False, font = TOOLBAR_FONT),
        ],
        [sg.Text('Protocols',font = TOOLBAR_FONT), hystogram, curves],
        [sg.Multiline(default_text = HELLO_MESSAGE, text_color = 'white', key = 'OUT', 
                      font = OUTPUT_SCREEN_FONT, 
                      size = OUTPUT_SCREEN_SIZE, disabled = True, autoscroll = False,
                      background_color= 'black')],
    ]

    # Create the Window
    window = sg.Window('Packet Sniffer', layout, size = WINDOW_SIZE)

    curves = window['trend']
    instant = 0; 

    prevX = 0
    
    prevYARP  = 0; newYARP  = 0
    prevYICMP = 0; newYICMP = 0
    prevYTCP  = 0; newYTCP  = 0
    prevYUDP  = 0; newYUDP  = 0

    xAxis      = []
    yAxisARP   = []
    yAxisICMP  = []
    yAxisTCP   = []
    yAxisUDP   = []
    
    for _ in range(SAMPLES+1): 
        xAxis.append(0)
        yAxisARP.append(0)
        yAxisICMP.append(0)
        yAxisTCP.append(0)
        yAxisUDP.append(0)


    while True:
        # If the user wants to sniff the traffic and the socket has been opened
        if (startCapture == True & socketOpened == True):
            packet, _ = sock.recvfrom(BUFFER_SIZE) 
            # Create a new parser thread
            parser = ParserThread(target=packetParser, args=(nPacket, packet, sniffARP, sniffICMP, sniffTCP, sniffUDP, protocolCounters))
            parser.start()
            result = parser.join()
            sniffOutput += result
            nPacket += 1
            # Update the video
            window['OUT'].update(sniffOutput)
        if (startCapture == True & socketOpened == False):
            sock = startSniffing()
            socketOpened = True
        # Window events
        event, points = window.read(timeout=500)
        if points['ARP']  == True: sniffARP  = True
        if points['ICMP'] == True: sniffICMP = True
        if points['TCP']  == True: sniffTCP  = True
        if points['UDP']  == True: sniffUDP  = True
        if points['ARP']  == False: sniffARP  = False
        if points['ICMP'] == False: sniffICMP = False
        if points['TCP']  == False: sniffTCP  = False
        if points['UDP']  == False: sniffUDP  = False

        if event == sg.WIN_CLOSED:
            break

        if event == 'Start':
            startCapture = True
            window['Start'].update(disabled=True)
            window['Stop'].update(disabled=False)
            window['OUT'].update(autoscroll=True)

        if event == 'Stop':
            socketOpened = False
            window['Start'].update(disabled=True)
            window['Stop'].update(disabled=True)
            window['Continue'].update(disabled=False)
            window['OUT'].update(autoscroll=False)

        if event == 'Continue':
            socketOpened = True
            window['Continue'].update(disabled=True)
            window['Stop'].update(disabled=False)
            window['OUT'].update(autoscroll=True)
        hystogram.erase()
        if(nPacket > 0):
            relARP  = (protocolCounters[0] / nPacket) * 100
            relTCP  = (protocolCounters[1] / nPacket) * 100
            relUDP  = (protocolCounters[2] / nPacket) * 100
            relICMP = (protocolCounters[3] / nPacket) * 100
        for i, x in enumerate([relARP, relTCP, relUDP, relICMP]):
            hystogram.draw_rectangle(top_left = (i * BAR_SPACING + EDGE_OFFSET, x),
            bottom_right = (i * BAR_SPACING + EDGE_OFFSET + BAR_WIDTH, 0), fill_color = COLORS[i])

        hystogram.draw_text(text = 'ARP:  {} {:.2f}%'.format(protocolCounters[0], relARP),location = (100, 20), color = 'blue', font = TOOLBAR_FONT)
        hystogram.draw_text(text = 'TCP:  {} {:.2f}%'.format(protocolCounters[1], relTCP),location = (100, 40), color = 'red', font = TOOLBAR_FONT)
        hystogram.draw_text(text = 'UDP:  {} {:.2f}%'.format(protocolCounters[2], relUDP),location = (100, 60), color = 'green', font = TOOLBAR_FONT)
        hystogram.draw_text(text = 'ICMP: {} {:.2f}%'.format(protocolCounters[3], relICMP),location = (100, 80), color = 'magenta', font = TOOLBAR_FONT)

        #Insert instant time
        xAxis.insert(i, instant)
        #Insert statistics
        yAxisARP.insert(i,  relTCP if relARP  <= SAMPLE_MAX else SAMPLE_MAX)
        yAxisICMP.insert(i, relICMP if relICMP <= SAMPLE_MAX else SAMPLE_MAX)
        yAxisTCP.insert(i,  relTCP if relTCP  <= SAMPLE_MAX else SAMPLE_MAX)
        yAxisUDP.insert(i,  relUDP if relUDP  <= SAMPLE_MAX else SAMPLE_MAX)

        newX     = xAxis[i]
        newYARP  = yAxisARP[i]
        newYICMP = yAxisICMP[i]
        newYTCP  = yAxisTCP[i]
        newYUDP  = yAxisUDP[i]

        if instant >= SAMPLES:
            # Shift graph over if full of data
            curves.move(-STEP_SIZE, 0)
            prevX = prevX - STEP_SIZE
            # Shift the array data points
            for i in range(SAMPLES):
                yAxisARP[i]  = yAxisARP[i+1]
                yAxisICMP[i] = yAxisICMP[i+1]
                yAxisTCP[i]  = yAxisTCP[i+1]
                yAxisUDP[i]  = yAxisUDP[i+1]
                xAxis[i]     = xAxis[i+1]
        curves.draw_line((prevX, prevYARP),  (newX, newYARP),  color='blue')
        curves.draw_line((prevX, prevYICMP), (newX, newYICMP), color='magenta')
        curves.draw_line((prevX, prevYTCP),  (newX, newYTCP),  color='red')
        curves.draw_line((prevX, prevYUDP),  (newX, newYUDP),  color='green')
        prevX, prevYARP  = newX, newYARP
        prevX, prevYICMP = newX, newYICMP
        prevX, prevYTCP  = newX, newYTCP
        prevX, prevYUDP  = newX, newYUDP
        instant += STEP_SIZE if i < SAMPLES else 0

        
    # Closing the program
    window.close()


main()
