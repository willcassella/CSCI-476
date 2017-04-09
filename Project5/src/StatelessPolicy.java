import java.util.ArrayList;
import java.util.regex.Pattern;

/**
 * Created by Will on 4/9/2017.
 */
public class StatelessPolicy extends Policy
{
    public enum Protocol
    {
        TCP,
        UDP
    }

    public static int FLAG_S = 1;
    public static int FLAG_A = 2;
    public static int FLAG_F = 4;
    public static int FLAG_R = 8;
    public static int FLAG_P = 16;
    public static int FLAG_U = 32;

    public static class SubPolicy
    {
        public SubPolicy()
        {
            type = null;
            pattern = null;
            flags = 0;
        }

        public SubPolicyType type;
        public Pattern pattern;
        public Integer flags;
    }

    public StatelessPolicy()
    {
        protocol = null;
        host_port = null;
        attacker_port = null;
        attacker_ip = null;
        sub_policies = new ArrayList<>();
    }

    public Protocol protocol;
    public Integer host_port;
    public Integer attacker_port;
    public String attacker_ip;
    public ArrayList<SubPolicy> sub_policies;
}
