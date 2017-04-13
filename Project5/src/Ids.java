/**
 * Created by Will on 3/5/2017.
 */

import org.jnetpcap.packet.JPacket;

public interface Ids
{
    void handlePacket(JPacket packet);

    void finished();
}