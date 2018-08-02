package test.org.opensc.pkcs15;

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertNotNull;

import org.opensc.pkcs15.AIDs;
import org.opensc.pkcs15.application.Application;
import org.opensc.pkcs15.application.ApplicationFactory;
import org.opensc.pkcs15.asn1.PKCS15AuthenticationObject;
import org.opensc.pkcs15.asn1.PKCS15Certificate;
import org.opensc.pkcs15.asn1.PKCS15Objects;
import org.opensc.pkcs15.asn1.PKCS15PublicKey;
import org.opensc.pkcs15.asn1.sequence.SequenceOf;
import org.opensc.pkcs15.token.PathHelper;
import org.opensc.pkcs15.token.Token;
import org.opensc.pkcs15.token.TokenContext;
import org.opensc.pkcs15.token.TokenFactory;
import org.opensc.pkcs15.token.TokenPath;

public class TestSurfnetToken extends HardwareCardSupport {

    private final static TokenFactory tokenFactory = TokenFactory.newInstance();
    private final static ApplicationFactory applicationFactory = ApplicationFactory.newInstance();

    private void testAuthObject(PKCS15Objects objs) {
        SequenceOf<PKCS15AuthenticationObject> auths = objs.getAuthObjects();
        List<PKCS15AuthenticationObject> list = auths.getSequence();
        PKCS15AuthenticationObject pin = list.get(0);
        System.out.println(pin.getCommonObjectAttributes().getLabel());
    }

    private void testPublicKeys(PKCS15Objects objs) {
        SequenceOf<PKCS15PublicKey> pubkeys = objs.getPublicKeys();
        List<PKCS15PublicKey> list = pubkeys.getSequence();
        System.out.println(list);
    }

    private void testCertificates(PKCS15Objects objs) {
        SequenceOf<PKCS15Certificate> cerficates = objs.getCertificates();
        List<PKCS15Certificate> list = cerficates.getSequence();
        for (PKCS15Certificate pkcs15certificate : list) {
            try {
                Certificate certificate = pkcs15certificate.getSpecificCertificateAttributes().getCertificateObject().getCertificate();
                System.out.println(certificate);
            } catch (CertificateParsingException ex) {
                Logger.getLogger(TestSurfnetToken.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    public void testApplicationFactory() throws IOException
    {
        Token token = tokenFactory.newHardwareToken(this.card);
        List<Application> apps = applicationFactory.listApplications(token);

        assertNotNull(apps);
        assertEquals(1,apps.size());
        Application app = apps.get(0);
        assertEquals(AIDs.PKCS15_AID, app.getAID());
        PathHelper.selectDF(token,new TokenPath(app.getApplicationTemplate().getPath()));

        token.selectEF(0x5031);

        PKCS15Objects objs = PKCS15Objects.readInstance(token.readEFData(),new TokenContext(token));
        testAuthObject(objs);
        //testPublicKeys(objs);
        //testCertificates(objs);
    }
}
