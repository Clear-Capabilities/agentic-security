using System;
using System.Net.Sockets;
using System.Threading.Tasks;

public class Relay
{
    private UdpClient _socket;
    private bool _running = true;

    private async Task Pump()
    {
        try
        {
            while (_running)
            {
                UdpReceiveResult got;
                try
                {
                    got = await _socket.ReceiveAsync();
                }
                catch (ObjectDisposedException) { break; }

                try
                {
                    HandlePacket(got.Buffer, got.RemoteEndPoint);
                }
                catch (Exception bad)
                {
                    Console.WriteLine("dropped packet: " + bad.Message);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
        }
    }

    private void HandlePacket(byte[] data, System.Net.IPEndPoint from) { }
}
