#GUI library importing
import PySimpleGUI as sg
#Socket library importing
import socket
#Parser library importing
from netparser import packetParser
# Thread library importing
from threading import Thread
import re, uuid

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
BAR_SPACING     = 100
EDGE_OFFSET     = 170
HYSTO_SIZE      = (900,100)
DATA_SIZE       = (700,100)
COLORS          = ['blue','red','green', 'magenta']




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

    counters = [0,0,0,0]   

    relARP  = 0
    relICMP = 0
    relTCP  = 0
    relUDP  = 0

    # Defining a theme
    sg.theme(APP_THEME)
    # All the stuff inside your window.
    hystogram = sg.Graph(HYSTO_SIZE, (0,0), DATA_SIZE, background_color = 'black')
    curves    = sg.Graph(HYSTO_SIZE, (0,0), DATA_SIZE, background_color = 'black')
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
        [sg.Text('Statististics',font = TOOLBAR_FONT), hystogram, curves],
        [sg.Multiline(default_text = HELLO_MESSAGE, text_color = 'white', key = 'OUT', 
                      font = OUTPUT_SCREEN_FONT, 
                      size = OUTPUT_SCREEN_SIZE, disabled = True, autoscroll = False,
                      background_color= 'black')],
    ]

    # Create the Window
    window = sg.Window('Packet Sniffer', layout, size = WINDOW_SIZE)

    while True:
        # If the user wants to sniff the traffic and the socket has been opened
        if (startCapture == True & socketOpened == True):
            packet, _ = sock.recvfrom(BUFFER_SIZE) 
            # Create a new parser thread
            parser = ParserThread(target=packetParser, args=(nPacket, packet, sniffARP, sniffICMP, sniffTCP, sniffUDP, counters))
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

        event, values = window.read(timeout=1000)
        if values['ARP']  == True: sniffARP  = True
        if values['ICMP'] == True: sniffICMP = True
        if values['TCP']  == True: sniffTCP  = True
        if values['UDP']  == True: sniffUDP  = True
        if values['ARP']  == False: sniffARP  = False
        if values['ICMP'] == False: sniffICMP = False
        if values['TCP']  == False: sniffTCP  = False
        if values['UDP']  == False: sniffUDP  = False

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
            relARP  = (counters[0] / nPacket) * 100
            relTCP  = (counters[1] / nPacket) * 100
            relUDP  = (counters[2] / nPacket) * 100
            relICMP = (counters[3] / nPacket) * 100
        for i, x in enumerate([relARP, relTCP, relUDP, relICMP]):
            hystogram.draw_rectangle(top_left = (i * BAR_SPACING + EDGE_OFFSET, x),
            bottom_right = (i * BAR_SPACING + EDGE_OFFSET + BAR_WIDTH, 0), fill_color = COLORS[i])
        hystogram.draw_text(text = '  ARP:  {} {:.2f}%'.format(counters[0], relARP),location=(70, 20), color = 'blue', font = TOOLBAR_FONT)
        hystogram.draw_text(text = '  TCP:  {} {:.2f}%'.format(counters[1], relTCP),location=(70, 40), color = 'red', font = TOOLBAR_FONT)
        hystogram.draw_text(text = '  UDP:  {} {:.2f}%'.format(counters[2], relUDP),location=(70, 60), color = 'green', font = TOOLBAR_FONT)
        hystogram.draw_text(text = '  ICMP: {} {:.2f}%'.format(counters[3], relICMP),location=(70, 80), color = 'magenta', font = TOOLBAR_FONT)

    # Closing the program
    window.close()


main()
