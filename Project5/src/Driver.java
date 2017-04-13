import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;

import java.io.BufferedReader;
import java.io.FileReader;
import java.nio.Buffer;
import java.rmi.server.ExportException;
import java.util.ArrayList;
import java.util.regex.Pattern;

/**
 * Created by Will on 4/12/2017.
 */
public class Driver
{
    private static class PacketIterator implements JPacketHandler<Ids[]>
    {
        @Override
        public void nextPacket(JPacket packet, Ids[] ids_array)
        {
            for (Ids ids : ids_array)
            {
                ids.handlePacket(packet);
            }
        }
    }

    public static ArrayList<Policy> parse_file(BufferedReader reader) throws java.io.IOException
    {
        ArrayList<Policy> result = new ArrayList<>();

        // Get the host
        final String host = parse_host(reader);
        reader.readLine();
        reader.readLine();

        Policy policy = parse_policy(reader);
        while (policy != null)
        {
            policy.host_ip = host;
            result.add(policy);
            policy = parse_policy(reader);
        }

        return result;
    }

    public static String parse_host(BufferedReader reader) throws java.io.IOException
    {
        String line = reader.readLine();
        return line.split("=")[1];
    }

    public static Policy parse_policy(BufferedReader reader) throws java.io.IOException
    {
        // Parse the name
        String line = reader.readLine();
        if (line == null)
        {
            return null;
        }

        final String name = line.split("=")[1];

        // Parse the type
        line = reader.readLine();
        final String type = line.split("=")[1];
        if (type.equals("stateful"))
        {
            Policy result =  parse_stateful_policy(reader);
            result.name = name;
            return result;
        }
        else if (type.equals("stateless"))
        {
            Policy result = parse_stateless_policy(reader);
            result.name = name;
            return result;
        }
        else
        {
            return null;
        }
    }

    public static StatefulPolicy parse_stateful_policy(BufferedReader reader) throws java.io.IOException
    {
        final StatefulPolicy result = new StatefulPolicy();

        // Parse host port
        String line = reader.readLine();
        final String host_port_str = line.split("=")[1];
        if (host_port_str.equals("any"))
        {
            result.host_port = null;
        }
        else
        {
            result.host_port = Integer.valueOf(host_port_str);
        }

        // Parse attacker port
        line = reader.readLine();
        final String attacker_port_str = line.split("=")[1];
        if (attacker_port_str.equals("any"))
        {
            result.attacker_port = null;
        }
        else
        {
            result.attacker_port = Integer.valueOf(attacker_port_str);
        }

        // Parse attacker ip
        line = reader.readLine();
        final String attacker_ip = line.split("=")[1];
        if (attacker_ip.equals("any"))
        {
            result.attacker_port = null;
        }
        else
        {
            result.attacker_ip = attacker_ip;
        }

        // Parse regex and from_host/to_host
        line = reader.readLine();
        final String[] sub_policy = line.split("=");
        if (sub_policy[0].equals("to_host"))
        {
            result.type = Policy.SubPolicyType.TO_HOST;
        }
        else
        {
            result.type = Policy.SubPolicyType.FROM_HOST;
        }

        result.regex = Pattern.compile(sub_policy[1].split("\"")[1]);

        return result;
    }

    public static StatelessPolicy parse_stateless_policy(BufferedReader reader) throws java.io.IOException
    {
        final StatelessPolicy result = new StatelessPolicy();

        // Parse protocol
        String line = reader.readLine();
        final String proto_str = line.split("=")[1];
        if (proto_str.equals("tcp"))
        {
            result.protocol = StatelessPolicy.Protocol.TCP;
        }
        else if (proto_str.equals("udp"))
        {
            result.protocol = StatelessPolicy.Protocol.UDP;
        }
        else
        {
            return null;
        }

        // Parse host port
        line = reader.readLine();
        final String host_port_str = line.split("=")[1];
        if (host_port_str.equals("any"))
        {
            result.host_port = null;
        }
        else
        {
            result.host_port = Integer.valueOf(host_port_str);
        }

        // Parse attacker port
        line = reader.readLine();
        final String attacker_port_str = line.split("=")[1];
        if (attacker_port_str.equals("any"))
        {
            result.attacker_port = null;
        }
        else
        {
            result.attacker_port = Integer.valueOf(attacker_port_str);
        }

        // Parse attacker ip
        line = reader.readLine();
        final String attacker_ip = line.split("=")[1];
        if (attacker_ip.equals("any"))
        {
            result.attacker_ip = null;
        }
        else
        {
            result.attacker_ip = attacker_ip;
        }

        // Parse sub policies
        parse_stateless_sub_policy(reader, result.sub_policies);

        return result;
    }

    public static void parse_stateless_sub_policy(
            BufferedReader reader,
            ArrayList<StatelessPolicy.SubPolicy> out) throws java.io.IOException
    {
        String line = reader.readLine();
        while (line != null && !line.isEmpty())
        {
            StatelessPolicy.SubPolicy result = new StatelessPolicy.SubPolicy();
            final String[] sub_policy = line.split("=");
            if (sub_policy[0].equals("to_host"))
            {
                result.type = Policy.SubPolicyType.TO_HOST;
            }
            else
            {
                result.type = Policy.SubPolicyType.FROM_HOST;
            }

            result.regex = Pattern.compile(sub_policy[1].split("\"")[1]);
            out.add(result);
            line = reader.readLine();
        }
    }

    public static Ids[] create_ids_array(ArrayList<Policy> policies)
    {
        Ids[] result = new Ids[policies.size()];

        for (int i = 0; i < policies.size(); ++i)
        {
            if (policies.get(i) instanceof StatelessPolicy)
            {
                result[i] = new StatelessIds((StatelessPolicy)policies.get(i));
            }
            else
            {
                result[i] = new StatefulIds((StatefulPolicy)policies.get(i));
            }
        }

        return result;
    }

    public static void main(String[] args)
    {
        final String config_path = args[0];
        final String pcap_path = args[1];

        // Load policies
        ArrayList<Policy> policies;
        try
        {
            policies = parse_file(new BufferedReader(new FileReader(config_path)));
        }
        catch (Exception e)
        {
            return;
        }

        // Create Ids array
        Ids[] ids_array = create_ids_array(policies);

        // Load pcap file
        StringBuilder errbuf = new StringBuilder();
        final Pcap pcap = Pcap.openOffline(pcap_path, errbuf);
        if (pcap == null)
        {
            System.err.println(errbuf);
            return;
        }

        // Check policies
        pcap.loop(Pcap.LOOP_INFINITE, new PacketIterator(), ids_array);

        // Run 'finished' callback
        for (Ids ids : ids_array)
        {
            ids.finished();
        }

        // Close the file
        pcap.close();
    }
}
