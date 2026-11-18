package demo;

import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.InputStream;
import java.io.StringWriter;

public class Converter {
    public String normalize(InputStream body) throws Exception {
        StreamSource input = new StreamSource(body);
        StringWriter out = new StringWriter();
        TransformerFactory.newInstance().newTransformer().transform(input, new StreamResult(out));
        return out.toString();
    }
}
