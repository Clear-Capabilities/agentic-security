import java.io.ObjectInputStream;
import java.io.FileInputStream;

public class Vuln {
    public Object readNative(java.io.InputStream in) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in);
        return ois.readObject();
    }

    public Object readXmlDecoder(java.io.InputStream in) {
        return new java.beans.XMLDecoder(in).readObject();
    }

    public Object readXStream(String xml) {
        com.thoughtworks.xstream.XStream xs = new com.thoughtworks.xstream.XStream();
        return xs.fromXML(xml);
    }

    public Object readFastJson(String json) {
        return com.alibaba.fastjson.JSON.parseObject(json, Object.class);
    }

    public Object readYaml(String src) {
        org.yaml.snakeyaml.Yaml y = new org.yaml.snakeyaml.Yaml();
        return y.load(src);
    }
}
