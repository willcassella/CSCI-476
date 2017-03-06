/**
 * Created by Will on 3/5/2017.
 */

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import java.net.InetAddress;
import java.util.HashMap;

public class scannerfinder
{
    private static class PacketCount
    {
        public InetAddress address = null;
        public int num_syn_packets_received = 0;
        public int num_syn_ack_packets_sent = 0;
    }

    private static class PacketHandler implements JPacketHandler<HashMap<Integer, PacketCount>>
    {
        private final Ip4 ip = new Ip4();
        private final Tcp tcp = new Tcp();

        public void nextPacket(JPacket packet, HashMap<Integer, PacketCount> ip_counter)
        {
            // Make sure it's an IPv4 packet
            if (!packet.hasHeader(ip))
            {
                return;
            }

            // Make sure it's a TCP packet
            if (!packet.hasHeader(tcp))
            {
                return;
            }

            // If it's a syn-ack packet
            if (tcp.flags_SYN() && tcp.flags_ACK())
            {
                // Get the destination and associated counter
                int destination = ip.destinationToInt();
                PacketCount count = ip_counter.get(destination);

                // If we don't already have an entry for this destination
                if (count == null)
                {
                    count = new PacketCount();
                    try
                    {
                        count.address = InetAddress.getByAddress(ip.destination());
                    }
                    catch (Exception e)
                    {
                        System.out.println("ERROR: " + e.getMessage());
                    }

                    ip_counter.put(destination, count);
                }

                // Increment the number of syn-acks sent for this IP
                count.num_syn_ack_packets_sent += 1;
                return;
            }

            // If it's a SYN packet
            if (tcp.flags_SYN())
            {
                // Get the source and associated counter
                int source = ip.sourceToInt();
                PacketCount count = ip_counter.get(source);

                // If we don't already have an entry for this source
                if (count == null)
                {
                    count = new PacketCount();
                    try
                    {
                        count.address = InetAddress.getByAddress(ip.source());
                    }
                    catch (Exception e)
                    {
                        System.out.println("ERROR: " + e.getMessage());
                    }

                    ip_counter.put(source, count);
                }

                // Increment the number of sys received from this IP
                count.num_syn_packets_received += 1;
                return;
            }
        }
    }

    public static void main(String[] args)
    {
        String path = args[0];

        StringBuilder errbuf = new StringBuilder();
        final Pcap pcap = Pcap.openOffline(path, errbuf);
        if (pcap == null)
        {
            System.err.println(errbuf);
            return;
        }

        // Read occurrences between desitnation ips and number of SYNS/SYN-ACKS sent and received
        HashMap<Integer, PacketCount> ip_counter = new HashMap<>();
        pcap.loop(Pcap.LOOP_INFINITE, new PacketHandler(), ip_counter);

        // Close the file
        pcap.close();

        // Figure out which Ip's were sending too many SYNS
        for (PacketCount ip_count : ip_counter.values())
        {
            if (ip_count.num_syn_packets_received > ip_count.num_syn_ack_packets_sent * 3)
            {
                System.out.println(ip_count.address.getHostAddress());
            }
        }
    }
}