using System.Collections.Generic;

public class Record
{
    public List<uint> Items = new List<uint>();

    public static Record Parse(byte[] data, int start)
    {
        var rec = new Record();
        ushort itemCount = Wire.ReadUInt16(data, start + 2);
        int pos = start + 4;
        for (int i = 0; i < itemCount; i++)
        {
            rec.Items.Add(Wire.ReadUInt32(data, pos));
            pos += 4;
        }
        return rec;
    }
}
