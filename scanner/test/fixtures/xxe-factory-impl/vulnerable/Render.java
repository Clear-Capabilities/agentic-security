import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamSource;
import java.io.StringReader;

public class Render {
    public Transformer stylesheet(String xsl) throws Exception {
        TransformerFactory factory = new org.example.xslt.TransformerFactoryImpl();
        return factory.newTransformer(new StreamSource(new StringReader(xsl)));
    }
}
