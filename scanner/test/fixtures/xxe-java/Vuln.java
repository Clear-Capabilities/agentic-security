// Vulnerable: DocumentBuilderFactory without disallow-doctype-decl
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.xml.sax.InputSource;

public class Vuln {
    public void parse(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        db.parse(new InputSource(new java.io.StringReader(xml)));
    }
    public void sax(String xml) throws Exception {
        javax.xml.parsers.SAXParserFactory spf = javax.xml.parsers.SAXParserFactory.newInstance();
    }
    public void stax(String xml) throws Exception {
        javax.xml.stream.XMLInputFactory xif = javax.xml.stream.XMLInputFactory.newInstance();
    }
}
