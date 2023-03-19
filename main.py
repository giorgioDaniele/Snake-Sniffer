#GUI library importing
import PySimpleGUI as sg
#Socket library importing
import socket
#Parser library importing
from netparser import packetParser
# Thread library importing
from threading import Thread
# Importing constants
import constants as const

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

def startSniffing():
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(const.ALL_PACKETS))
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
    sg.theme(const.APP_THEME)

    hystogram = sg.Graph(const.HYSTO_SIZE,  (0,0), const.DATA_SIZE, background_color = 'black')
    curves    = sg.Graph(const.CANVAS_SIZE, (0,0), (const.SAMPLES, const.SAMPLE_MAX), background_color = 'black', key = 'trend')


    layout = [
        [
        sg.Button('Start', key = 'Start', font = const.TOOLBAR_FONT, disabled = False),
        sg.Button('Stop', key = 'Stop',   font = const.TOOLBAR_FONT, disabled = True),
        sg.Button('Continue',  key = 'Continue',  font = const.TOOLBAR_FONT, disabled = True),
        sg.Checkbox('ARP', text_color = 'blue', key = 'ARP', default = False, font = const.TOOLBAR_FONT),
        sg.Checkbox('ICMP', text_color = 'magenta', key = 'ICMP', default = False, font = const.TOOLBAR_FONT),
        sg.Checkbox('TCP', text_color = 'red', key = 'TCP', default = False, font = const.TOOLBAR_FONT),
        sg.Checkbox('UDP', text_color = 'green', key = 'UDP', default = False, font = const.TOOLBAR_FONT),
        ],
        [sg.Text('Protocols',font = const.TOOLBAR_FONT), hystogram, curves],
        [sg.Multiline(default_text = const.HELLO_MESSAGE, text_color = 'white', key = 'OUT', 
                      font = const.OUTPUT_SCREEN_FONT, 
                      size = const.OUTPUT_SCREEN_SIZE, disabled = True, autoscroll = False,
                      background_color= 'black')],
    ]

    # Create the Window
    window = sg.Window('Packet Sniffer', layout, size = const.WINDOW_SIZE)

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
    
    for _ in range(const.SAMPLES+1): 
        xAxis.append(0)
        yAxisARP.append(0)
        yAxisICMP.append(0)
        yAxisTCP.append(0)
        yAxisUDP.append(0)


    while True:
        # If the user wants to sniff the traffic and the socket has been opened
        if (startCapture == True & socketOpened == True):
            packet, _ = sock.recvfrom(const.BUFFER_SIZE) 
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
            hystogram.draw_rectangle(top_left = (i * const.BAR_SPACING + const.EDGE_OFFSET, x),
            bottom_right = (i * const.BAR_SPACING + const.EDGE_OFFSET + const.BAR_WIDTH, 0), fill_color = const.COLORS[i])

        hystogram.draw_text(text = 'ARP:  {} {:.2f}%'.format(protocolCounters[0], relARP),location = (100, 20), color = 'blue', font = const.TOOLBAR_FONT)
        hystogram.draw_text(text = 'TCP:  {} {:.2f}%'.format(protocolCounters[1], relTCP),location = (100, 40), color = 'red', font = const.TOOLBAR_FONT)
        hystogram.draw_text(text = 'UDP:  {} {:.2f}%'.format(protocolCounters[2], relUDP),location = (100, 60), color = 'green', font = const.TOOLBAR_FONT)
        hystogram.draw_text(text = 'ICMP: {} {:.2f}%'.format(protocolCounters[3], relICMP),location = (100, 80), color = 'magenta', font = const.TOOLBAR_FONT)

        #Insert instant time
        xAxis.insert(i, instant)
        #Insert statistics
        yAxisARP.insert(i,  relARP  if relARP  <= const.SAMPLE_MAX else const.SAMPLE_MAX)
        yAxisICMP.insert(i, relICMP if relICMP <= const.SAMPLE_MAX else const.SAMPLE_MAX)
        yAxisTCP.insert(i,  relTCP  if relTCP  <= const.SAMPLE_MAX else const.SAMPLE_MAX)
        yAxisUDP.insert(i,  relUDP  if relUDP  <= const.SAMPLE_MAX else const.SAMPLE_MAX)

        newX     = xAxis[i]
        newYARP  = yAxisARP[i]
        newYICMP = yAxisICMP[i]
        newYTCP  = yAxisTCP[i]
        newYUDP  = yAxisUDP[i]

        if instant >= const.SAMPLES:
            # Shift graph over if full of data
            curves.move(- const.STEP_SIZE, 0)
            prevX = prevX - const.STEP_SIZE
            # Shift the array data points
            for i in range(const.SAMPLES):
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
        instant += const.STEP_SIZE if i < const.SAMPLES else 0
    # Closing the program
    window.close()


main()
