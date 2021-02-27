import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;

import org.opensaml.xml.security.Criteria;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.KeyStoreCredentialResolver;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.x509.X509Credential;

public class TestCredential {

    private static Credential getCredential(String entityId, String password, String keyStorePath) throws Exception {
        
        KeyStore keystore;
        keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        InputStream inputStream = TestCredential.class.getResourceAsStream(keyStorePath);
        //FileInputStream inputStream = new FileInputStream(keyStorePath);
        keystore.load(inputStream, password.toCharArray());
        inputStream.close();
        
        Map<String, String> passwordMap = new HashMap<String, String>();
        passwordMap.put(entityId, password);
        KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(keystore, passwordMap);
        
        Criteria criteria = new EntityIDCriteria(entityId);
        CriteriaSet criteriaSet = new CriteriaSet(criteria);
        
        X509Credential credential = (X509Credential)resolver.resolveSingle(criteriaSet); 
        System.out.println(credential);

        return credential;

    }

    public static void main(String args[]) throws Exception {

        getCredential("http://localhost:8080/SAML", "keystorepass", "keys/keystore-saml.jks");
    
        // KeyStore keystore;
        // keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        // FileInputStream inputStream = new FileInputStream("keystore.jks");
        // keystore.load(inputStream, "password".toCharArray());
        // inputStream.close();
        
        // Map<String, String> passwordMap = new HashMap<String, String>();
        // passwordMap.put("selfsigned", "password");
        // KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(keystore, passwordMap);
        
        // Criteria criteria = new EntityIDCriteria("selfsigned");
        // CriteriaSet criteriaSet = new CriteriaSet(criteria);
        
        // X509Credential credential = (X509Credential)resolver.resolveSingle(criteriaSet); 
        // System.out.println(credential);

    }

    

}