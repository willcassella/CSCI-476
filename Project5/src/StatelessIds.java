/**
 * Created by Will on 4/12/2017.
 */

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import java.util.regex.Matcher;

public class StatelessIds implements Ids
{
    private boolean triggered = false;
    private final StatelessPolicy policy;
    private final Ip4 ip = new Ip4();
    private final Tcp tcp = new Tcp();
    private final Udp udp = new Udp();
    private int sub_policy_index = 0;

    public StatelessIds(StatelessPolicy policy)
    {
        this.policy = policy;
    }

    @Override
    public void handlePacket(JPacket packet)
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

        String entry_ip;
        int entry_port;
        boolean success;
        if (source_ip.equals(policy.host_ip))
        {
            entry_ip = dest_ip;
            entry_port = source_port;
            success = check_from_host(policy, dest_port, dest_ip, source_port);
        }
        else
        {
            entry_ip = source_ip;
            entry_port = dest_port;
            success = check_to_host(policy, dest_port, source_ip, source_port);
        }

        if (!success)
        {
            return;
        }

        // Figure out if the payload matches
        Matcher matcher = policy.sub_policies.get(sub_policy_index).regex.matcher(payload);
        if (!matcher.find())
        {
            sub_policy_index = 0;
            return;
        }

        // If this is the last policy, we've found an intrusion
        sub_policy_index += 1;
        if (sub_policy_index == policy.sub_policies.size())
        {
            sub_policy_index = 0;
            triggered = true;
            System.out.println("Policy '" + policy.name + "' violated by connection to " + entry_ip + " on port " + entry_port + "!");
        }
    }

    @Override
    public void finished()
    {
        if (!triggered)
        {
            System.out.println("Policy '" + policy.name + "' found no violations.");
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

        // Check if the destination IP matches the policy
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
