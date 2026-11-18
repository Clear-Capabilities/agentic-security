package demo;

import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import java.io.StringWriter;

public class Converter {
    public String serialize(Document doc) throws Exception {
        DOMSource tree = new DOMSource(doc);
        StringWriter out = new StringWriter();
        TransformerFactory.newInstance().newTransformer().transform(tree, new StreamResult(out));
        return out.toString();
    }
}
