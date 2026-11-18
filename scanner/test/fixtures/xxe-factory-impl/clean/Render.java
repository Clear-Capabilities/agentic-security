import javax.xml.XMLConstants;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamSource;
import java.io.StringReader;

public class Render {
    public Transformer stylesheet(String xsl) throws Exception {
        TransformerFactory factory = new org.example.xslt.TransformerFactoryImpl();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        return factory.newTransformer(new StreamSource(new StringReader(xsl)));
    }
}
