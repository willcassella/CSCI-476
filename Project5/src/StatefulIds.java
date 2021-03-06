import org.jnetpcap.packet.JPacket;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import java.util.HashMap;
import java.util.regex.Matcher;

/**
 * Created by Will on 4/12/2017.
 */
public class StatefulIds implements Ids
{
    private boolean triggered = false;
    private final StatefulPolicy policy;
    private final Ip4 ip = new Ip4();
    private final Tcp tcp = new Tcp();
    private final HashMap<String, String> connections = new HashMap<>();

    public StatefulIds(StatefulPolicy policy)
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

        // Make sure it's a tcp packet
        if (!packet.hasHeader(tcp))
        {
            return;
        }

        // Get the destination port, source port, and payload
        int dest_port = tcp.destination();
        int source_port = tcp.source();
        String payload = packet.getUTF8String(tcp.getPayloadOffset(), tcp.getPayloadLength());
        String source_ip = org.jnetpcap.packet.format.FormatUtils.ip(ip.source());
        String dest_ip = org.jnetpcap.packet.format.FormatUtils.ip(ip.destination());

        // Figure out if this message is supposed to be to the host or from the host
        String entry_ip;
        int entry_port;
        boolean append;
        if (source_ip.equals(policy.host_ip))
        {
            entry_ip = dest_ip;
            entry_port = source_port;
            append = check_from_host(policy, dest_port, dest_ip, source_port);
        }
        else
        {
            entry_ip = source_ip;
            entry_port = dest_port;
            append = check_to_host(policy, dest_port, source_ip, source_port);
        }

        // Get the message for this entry
        String message = connections.getOrDefault(entry_ip, null);

        // If this is a new connection
        if (tcp.flags_SYN())
        {
            // If we ALREADY have a connection for this entry
            if (message != null)
            {
                return;
            }

            // Add a new entry
            connections.put(entry_ip, "");
            return;
        }
        // If this is a closing connection
        if (tcp.flags_FIN())
        {
            // If we don't have a connection for this entry
            if (message == null)
            {
                return;
            }

            // Check the message against the rule
            Matcher matcher = policy.regex.matcher(message);
            if (matcher.find())
            {
                triggered = true;
                System.out.println("Policy '" + policy.name + "' violated by connection to " + entry_ip + " on port " + entry_port + "!");
            }

            connections.remove(entry_ip);
            return;
        }

        // Add the payload to the message, and keep going
        if (message != null && append)
        {
            message += payload;
            connections.put(entry_ip, message);
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
            StatefulPolicy policy,
            int destination_port,
            String source_ip,
            int source_port)
    {
        // Check if the current rule is asking for a to_host message
        if (policy.type != Policy.SubPolicyType.TO_HOST)
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
            StatefulPolicy policy,
            int destination_port,
            String dest_ip,
            int source_port)
    {
        // Check if the current rule is asking for a from_host message
        if (policy.type != Policy.SubPolicyType.FROM_HOST)
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
