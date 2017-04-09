/**
 * Created by Will on 3/5/2017.
 */

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Ids
{
    private static class StatelessIds implements JPacketHandler<StatelessPolicy>
    {
        private final Ip4 ip = new Ip4();
        private final Tcp tcp = new Tcp();
        private final Udp udp = new Udp();
        private int sub_policy_index = 0;

        @Override
        public void nextPacket(JPacket packet, StatelessPolicy policy)
        {
            // Make sure it's an IPv4 packet
            if (!packet.hasHeader(ip))
            {
                return;
            }

            // Check if it's a tcp packet or udp packet
            int dest_port;
            int source_port;
            String payload;
            if (policy.protocol == StatelessPolicy.Protocol.TCP && packet.hasHeader(tcp))
            {
                dest_port = tcp.destination();
                source_port = tcp.source();
                payload = packet.getUTF8String(tcp.getPayloadOffset(), tcp.getPayloadLength());
            }
            else if (policy.protocol == StatelessPolicy.Protocol.UDP && packet.hasHeader(udp))
            {
                dest_port = udp.destination();
                source_port = udp.source();
                payload = packet.getUTF8String(udp.getPayloadOffset(), udp.getPayloadLength());
            }
            else
            {
                return;
            }

            // If the payload is empty, skip it
            if (payload.isEmpty())
            {
                return;
            }

            // Figure out if this packet is to the host or from the host
            String source_ip = org.jnetpcap.packet.format.FormatUtils.ip(ip.source());
            String dest_ip = org.jnetpcap.packet.format.FormatUtils.ip(ip.destination());

            boolean success;
            if (source_ip.equals(policy.host_ip))
            {
                success = check_from_host(policy, dest_port, dest_ip, source_port);
            }
            else
            {
                success = check_to_host(policy, dest_port, source_ip, source_port);
            }

            if (!success)
            {
                return;
            }

            // Figure out if the payload matches
            Matcher matcher = policy.sub_policies.get(sub_policy_index).pattern.matcher(payload);
            if (!matcher.find())
            {
                System.out.println(payload);
                sub_policy_index = 0;
                return;
            }

            // If this is the last policy, we've found an intrusion
            System.out.println(payload);
            sub_policy_index += 1;
            if (sub_policy_index == policy.sub_policies.size())
            {
                sub_policy_index = 0;
                System.out.println("Intrusion detected!");
            }
        }

        private boolean check_to_host(
                StatelessPolicy policy,
                int destination_port,
                String source_ip,
                int source_port)
        {
            // Check if the current rule is asking for a to_host message
            if (policy.sub_policies.get(sub_policy_index).type != Policy.SubPolicyType.TO_HOST)
            {
                return false;
            }

            // Check if the source port matches the rule
            if (policy.attacker_ip != null && !policy.attacker_ip.equals(source_ip))
            {
                return false;
            }

            // Check if the destination port matches the policy
            if (policy.host_port != null && destination_port != policy.host_port)
            {
                return false;
            }

            // Check if the source port matches the policy
            if (policy.attacker_port != null && source_port != policy.attacker_port)
            {
                return false;
            }

            return true;
        }

        private boolean check_from_host(
                StatelessPolicy policy,
                int destination_port,
                String dest_ip,
                int source_port)
        {
            // Check if the current rule is asking for a from_host message
            if (policy.sub_policies.get(sub_policy_index).type != Policy.SubPolicyType.FROM_HOST)
            {
                return false;
            }

            // Check if the desination IP matches the policy
            if (policy.attacker_ip != null && !policy.attacker_ip.equals(dest_ip))
            {
                return false;
            }

            // Check if the destination port matches the policy
            if (policy.attacker_port != null && destination_port != policy.attacker_port)
            {
                return false;
            }

            // Check if the source port matches the policy
            if (policy.host_port != null && source_port != policy.host_port)
            {
                return false;
            }

            return true;
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

//        // Create a policy for the first part
//        StatelessPolicy policy = new StatelessPolicy();
//        policy.host_ip = "192.168.0.1";
//        policy.name = "Blame Attack 1";
//        policy.protocol = StatelessPolicy.Protocol.TCP;
//        policy.host_port = 110;
//
//        StatelessPolicy.SubPolicy sub_policy = new StatelessPolicy.SubPolicy();
//        sub_policy.type = Policy.SubPolicyType.FROM_HOST;
//        sub_policy.pattern = Pattern.compile("OK.*\r\n");
//        policy.sub_policies.add(sub_policy);
//
//        sub_policy = new StatelessPolicy.SubPolicy();
//        sub_policy.type = Policy.SubPolicyType.TO_HOST;
//        sub_policy.pattern = Pattern.compile("USER .*\r\n");
//        policy.sub_policies.add(sub_policy);
//
//        sub_policy = new StatelessPolicy.SubPolicy();
//        sub_policy.type = Policy.SubPolicyType.FROM_HOST;
//        sub_policy.pattern = Pattern.compile("OK.*\r\n");
//        policy.sub_policies.add(sub_policy);
//
//        sub_policy = new StatelessPolicy.SubPolicy();
//        sub_policy.type = Policy.SubPolicyType.TO_HOST;
//        sub_policy.pattern = Pattern.compile("PASS.*\r\n");
//        policy.sub_policies.add(sub_policy);
//
//        sub_policy = new StatelessPolicy.SubPolicy();
//        sub_policy.type = Policy.SubPolicyType.FROM_HOST;
//        sub_policy.pattern = Pattern.compile("OK.*\r\n");
//        policy.sub_policies.add(sub_policy);

        StatelessPolicy policy = new StatelessPolicy();
        policy.host_ip = "192.168.0.1";
        policy.name = "TFTP Attacker boot";
        policy.protocol = StatelessPolicy.Protocol.UDP;
        policy.attacker_port = 69;

        StatelessPolicy.SubPolicy sub_policy = new StatelessPolicy.SubPolicy();
        sub_policy.type = Policy.SubPolicyType.FROM_HOST;
        sub_policy.pattern = Pattern.compile("vmlinuz");
        policy.sub_policies.add(sub_policy);

        sub_policy = new StatelessPolicy.SubPolicy();
        sub_policy.type = Policy.SubPolicyType.TO_HOST;
        sub_policy.pattern = Pattern.compile("\x00\x03\x00\x01");
        policy.sub_policies.add(sub_policy);

        // Check the policy
        pcap.loop(Pcap.LOOP_INFINITE, new StatelessIds(), policy);

        // Close the file
        pcap.close();
    }
}