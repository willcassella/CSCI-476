/**
 * Created by Will on 4/9/2017.
 */
public abstract class Policy
{
    public enum SubPolicyType
    {
        TO_HOST,
        FROM_HOST
    }

    public Policy()
    {
        host_ip = null;
        name = null;
    }

    public String host_ip;
    public String name;
}
