using System;
using System.Buffers.Binary;
using System.Net;

public class AddressAttribute
{
    public int Port;
    public IPAddress Address;

    public AddressAttribute(byte[] attributeValue)
    {
        Port = BinaryPrimitives.ReadUInt16BigEndian(attributeValue.AsSpan(2));
        Address = new IPAddress(new byte[] { attributeValue[4], attributeValue[5], attributeValue[6], attributeValue[7] });
    }

    public static uint Cookie(byte[] value)
    {
        return BitConverter.ToUInt32(value, 08) ^ 0x2112A442;
    }

    // A caller-visible length check elsewhere does not help: this method has none.
    protected byte Family(byte[] value)
    {
        return value[1];
    }
}
