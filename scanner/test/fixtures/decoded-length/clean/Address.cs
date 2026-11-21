using System;
using System.Buffers.Binary;
using System.Net;

public class AddressAttribute
{
    public int Port;
    public IPAddress Address;
    private const int MIN_LENGTH = 8;

    public AddressAttribute(byte[] attributeValue)
    {
        if (attributeValue == null || attributeValue.Length < MIN_LENGTH)
        {
            throw new ArgumentException("too short", nameof(attributeValue));
        }
        Port = BinaryPrimitives.ReadUInt16BigEndian(attributeValue.AsSpan(2));
        Address = new IPAddress(new byte[] { attributeValue[4], attributeValue[5], attributeValue[6], attributeValue[7] });
    }

    public static uint Cookie(byte[] value)
    {
        try
        {
            return BitConverter.ToUInt32(value, 08) ^ 0x2112A442;
        }
        catch (ArgumentException)
        {
            return 0;
        }
    }

    // Reads only the first two bytes: a parser that read one or two bytes is the common, caller-checked case.
    protected byte Family(byte[] value)
    {
        return value[1];
    }

    // A writer: the array is the destination.
    public void WriteTo(byte[] buffer)
    {
        buffer[2] = 0;
        buffer[3] = 1;
        BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(4), 7);
    }

    // The offset is a parameter, not a constant.
    public static ushort ReadAt(byte[] data, int offset)
    {
        return BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(offset));
    }

    // Private helpers are reached only through the checked members above.
    private static byte Third(byte[] value)
    {
        return value[3];
    }
}
