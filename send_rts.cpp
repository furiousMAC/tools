/*******************************************************************************
* send_rts.cpp -- a program to send a 802.11 Request-  To-Send (RTS) frame from
* a user-specified source MAC address to a user-specified destination MAC
* address  
*                                                      
* Author:  Erik Rye @gigaryte                             
*                                                        
* Purpose:  Sends an RTS frame from a (potentially spoofed) source MAC to a
* destination MAC. On many 802.11 mobile devices that are un-associated with a
* wireless network, they will respond with a Clear-To-Send (CTS) frame to the
* source MAC address if the destination MAC address matches their permanent
* 802.11 MAC address, even when in a pre-association MAC address randomization
* state. This is useful in the event that an individual knows the global MAC
* address of a device they wish to track, but is unaware of whether that device
* is within 802.11 transmission range. Similar code was used in the PETS 17
* paper "A Study of MAC Address Randomization in Mobile Devices and When it
* Fails", available at https://furiousmac.com/files/paper82-2017-4-source.pdf.
*
* Requires libtins and libpthread. 
*
* Compile with:
* g++ send_rts.cpp -o send_rts -O3 -std=c++11 -lpthread -ltins
*
* Usage:
* ./send_rts <interface> <source MAC> <dest MAC>
*
********************************************************/   
#include <iostream>
#include <set>
#include <string>
#include <tins/tins.h>
#include <unistd.h>
 
using std::set;
using std::cout;
using std::endl;
using std::string;
using std::runtime_error;

using namespace Tins;
 
int main(int argc, char* argv[]) {

    if (argc != 4) {
        cout << "Usage: " <<* argv << " <interface>" << 
          " <source MAC> <dest MAC>" << endl;
        return 1;
    }
    PacketSender sender;
    string iface = argv[1];
    string src = argv[2];
    string dest = argv[3];

    int uid = getuid();
    int euid = geteuid();

    if ((uid != 0) && (euid != 0)){
        cout << "[-] Hey! Run me as root!" << endl;
        return 1;
    }

    try {
      sender.default_interface(iface);
    }
    catch (runtime_error& ex) {
        cout << "[-] Error: " << ex.what() << endl;
        cout << "[-] Ok, buh-bye :(" << endl;
        return 1; 
    }

    cout << "[+] Got iface: " << iface << endl;
    cout << "[+] Source MAC address: " << src << endl;
    cout << "[+] Destination MAC address: " << dest << endl;
    cout << "[*] Time's up; let's do this. LEEEROYYY!" << endl;

    Dot11RTS rts = Dot11RTS(dest, src);
    RadioTap radio = RadioTap() / rts;

    cout << "[+] Starting send loop. Ctrl+C to quit." << endl;;
    while (true)
      sender.send(radio);

    return 0;
}
