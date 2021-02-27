
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPathExpressionException;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.impl.SAMLObjectContentReference;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml2.core.impl.AudienceBuilder;
import org.opensaml.saml2.core.impl.AudienceRestrictionBuilder;
import org.opensaml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnStatementBuilder;
import org.opensaml.saml2.core.impl.ConditionsBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationDataBuilder;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.saml2.core.NameID;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.io.*;
import org.opensaml.xml.schema.XSString;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.opensaml.xml.security.credential.Credential;
import java.security.*;
import javax.servlet.annotation.WebServlet;
import javax.servlet.ServletException;
import java.io.*;

import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;

@WebServlet(name = "/validateUser", urlPatterns = { "/validateUser" })
public class ValidateUser extends HttpServlet {

	

	// keytool -genkey -keyalg RSA -alias selfsigned -keystore keystore.jks -storepass lib123 -validity 360 -keysize 2048


	/*keytool -export -alias selfsigned -file mydomain.der -keystore keystore-saml.jks*/

	@Override
	public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
		String mailId = request.getParameter("mailId");
		String pass = request.getParameter("password");
		String samlRequest = request.getParameter("samlRequestId");
		String relayState=request.getParameter("relayState");
		System.out.println("in validate user rela state is"+relayState);

		if (samlRequest == null) {
			return;
			}
		 else {
			String status = Action.isValidUser(mailId, pass);
			if (!status.equals("valid")) {
				return;
			}
			Map<String,String> userAttributes=Action.getUserAttributes(mailId);
			AuthnRequest authnRequest = null;
			String samlResponseString = "";
			try {
				authnRequest = getAuthnRequest(samlRequest);
			} catch (Exception e) {
				System.out.println("Exception" + e);
			}
			
			String acsUrl = authnRequest.getAssertionConsumerServiceURL();
			System.out.println("ACSUrl: " + acsUrl);
			String requestId=authnRequest.getID();
			Response samlResponse = null;
			try {
				String sessionIndex=request.getSession().getId();
				samlResponse = getResponse(acsUrl, requestId,sessionIndex,userAttributes);
				samlResponse.setIssueInstant(new DateTime());
				Signature sig=signResponse(samlResponse);
				samlResponse.setSignature(sig);
				((SAMLObjectContentReference)sig.getContentReferences().get(0))
		        .setDigestAlgorithm(EncryptionConstants.ALGO_ID_DIGEST_SHA256);
				  try {
				   Configuration.getMarshallerFactory().getMarshaller(samlResponse)
				     .marshall(samlResponse);
				  } catch (MarshallingException e) {
				   e.printStackTrace();
				  }
				  try {
				   Signer.signObject(sig);
				  } catch (SignatureException e) {
				   e.printStackTrace();
				  }
				/*samlResponse.setSignature(sig);
				 try {
					   Configuration.getMarshallerFactory().getMarshaller(samlResponse)
					     .marshall(samlResponse);
					  } catch (MarshallingException e) {
					   e.printStackTrace();
					  }

					  try {
					   Signer.signObject(sig);
					  } catch (SignatureException e) {
					   e.printStackTrace();
					  }
				((SAMLObjectContentReference)sig.getContentReferences().get(0))
		        .setDigestAlgorithm(EncryptionConstants.ALGO_ID_DIGEST_SHA256);
				Signer.signObject(sig);
				*/
				//samlResponse.setSignature(newSignature);
			} catch (ConfigurationException e1) {
				e1.printStackTrace();
			} catch (MarshallingException e) {
				e.printStackTrace();
			} catch (XPathExpressionException e) {
				e.printStackTrace();
			} catch (GeneralSecurityException e) {
				e.printStackTrace();
			} catch (XMLSecurityException e) {
				e.printStackTrace();
			} //catch (SignatureException e) {
				//e.printStackTrace();
			//}
			try {
				samlResponseString = generateSAMLResponse(samlResponse);
			} catch (Exception e) {
				System.out.println("Exception" + e);
			}
			request.setAttribute("SAMLResponse", samlResponseString);
			request.setAttribute("RelayState",relayState);
			RequestDispatcher dispatcher = request.getServletContext().getRequestDispatcher("/ssoredirect.jsp");
			dispatcher.forward(request, response);
			return;
		}
	}

	private Response getResponse(String acsUrl, String requestId,String sessionIndex,Map<String,String>userAttributes) throws IOException, ConfigurationException, MarshallingException, XPathExpressionException, GeneralSecurityException, XMLSecurityException {
		Status status = SAMLBuilder.buildStatus(StatusCode.SUCCESS_URI);

		String entityId = "http://localhost:8080/SAML";
		Response authResponse = new ResponseBuilder().buildObject();
		Issuer issuer = SAMLBuilder.buildIssuer(entityId);
		authResponse.setIssuer(issuer);
		authResponse.setID(SAMLBuilder.randomSAMLId());
		authResponse.setIssueInstant(new DateTime());
		authResponse.setInResponseTo(requestId);
		Assertion assertion = buildAssertion(sessionIndex,userAttributes);
		authResponse.getAssertions().add(assertion);
		System.out.println("Assertiob is \t" + assertion);
		
		authResponse.setDestination(acsUrl);

		authResponse.setStatus(status);
		Marshaller marshaller = org.opensaml.Configuration.getMarshallerFactory().getMarshaller(authResponse);
		org.w3c.dom.Element authDOM = marshaller.marshall(authResponse);
		StringWriter rspWrt = new StringWriter();
		XMLHelper.writeNode(authDOM, rspWrt);
		String res = rspWrt.toString();
		
		return authResponse;
	}
	private static XMLObjectBuilderFactory builderFactory;
	public static XMLObjectBuilderFactory getSAMLBuilder() throws ConfigurationException {

		if (builderFactory == null) {
			// OpenSAML 2.3
			DefaultBootstrap.bootstrap();
			builderFactory = Configuration.getBuilderFactory();
		}

		return builderFactory;
	}
	public Assertion buildAssertion(String sessionIndex,Map<String,String>userAttributes) throws ConfigurationException {
		Assertion samlAssertion = new AssertionBuilder().buildObject();
		Issuer issuer = SAMLBuilder.buildIssuer("http://localhost:8080/SAML");
		samlAssertion.setIssuer(issuer);
		samlAssertion.setID(SAMLBuilder.randomSAMLId());
		samlAssertion.setIssueInstant(new DateTime());
		// subject
		/*Map<String, String> attributes = new HashMap<String, String>();
		attributes.put("firstName", "jaii");
		attributes.put("lastName", "jaii");
		attributes.put("email", "jaiiselvaraj@gmail.com");*/
		/*attributes.put("firstName", "okta");
		attributes.put("lastName", "okta");
		attributes.put("mail", "jaiilakshmi@gmail.com");
		attributes.put("userName","jaiilakshmi@gmail.com");*/
		samlAssertion.setVersion(SAMLVersion.VERSION_20);
		Subject subject = new SubjectBuilder().buildObject();
		// namId
		NameID nameId = new NameIDBuilder().buildObject();
		//nameId.setValue("jaiilakshmi@gmail.com");
		nameId.setValue(userAttributes.get("email"));
		nameId.setFormat(NameID.UNSPECIFIED);
		nameId.setNameQualifier("http://localhost:8080/SAML");		
		
		SAMLObjectBuilder confirmationMethodBuilder = (SAMLObjectBuilder)  SAMLWriter.getSAMLBuilder().getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
        SubjectConfirmationData confirmationMethod = (SubjectConfirmationData) confirmationMethodBuilder.buildObject();
        DateTime now = new DateTime();
        confirmationMethod.setNotBefore(now);
        confirmationMethod.setNotOnOrAfter(now.plusMinutes(2));
        confirmationMethod.setRecipient("https://dev-43055720.okta.com/sso/saml2/0oa8afzkun589XwAm5d6");

        SAMLObjectBuilder subjectConfirmationBuilder = (SAMLObjectBuilder) SAMLWriter.getSAMLBuilder().getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
        SubjectConfirmation subjectConfirmation = (SubjectConfirmation) subjectConfirmationBuilder.buildObject();
        subjectConfirmation.setSubjectConfirmationData(confirmationMethod);
        subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer");
        // Create the Subject
        SAMLObjectBuilder subjectBuilder = (SAMLObjectBuilder) SAMLWriter.getSAMLBuilder().getBuilder(Subject.DEFAULT_ELEMENT_NAME);
        Subject subject1 = (Subject) subjectBuilder.buildObject();

        subject1.setNameID(nameId);
        subject1.getSubjectConfirmations().add(subjectConfirmation);
		// subjectConfirmation
		/*SubjectConfirmation subjectConfirmation = new SubjectConfirmationBuilder().buildObject();
		subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer");
		SubjectConfirmationData subjectConfirmationData = new SubjectConfirmationDataBuilder().buildObject();
		subjectConfirmationData.setRecipient("https://dev-43055720.okta.com/sso/saml2/0oa8afzkun589XwAm5d6");
		//jaiiselvaraj				https://www.okta.com/saml2/service-provider/spkdluteneimsgrqynuj
		//subjectConfirmationData.setRecipient("https://dev-43055720.okta.com/sso/saml2/0oa8afzkun589XwAm5d6");
		DateTime now = new DateTime();
		subjectConfirmationData.setNotBefore(now);
		subjectConfirmationData.setNotOnOrAfter(now.plusMinutes(2));
		subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
		subject.getSubjectConfirmations().add(subjectConfirmation);
		*/
        
        //AuthnStatment
		AuthnStatement authStmt = new AuthnStatementBuilder().buildObject();
		authStmt.setSessionIndex(sessionIndex);
		authStmt.setAuthnInstant(new DateTime());
		
		//AuthContext
		AuthnContext authContext = new AuthnContextBuilder().buildObject();
		AuthnContextClassRef authCtxClassRef = new AuthnContextClassRefBuilder().buildObject();
		authCtxClassRef.setAuthnContextClassRef(AuthnContext.PPT_AUTHN_CTX);
		authContext.setAuthnContextClassRef(authCtxClassRef);
		authStmt.setAuthnContext(authContext);
		samlAssertion.getAuthnStatements().add(authStmt);
		
		//AudienceRestriction
		AudienceRestriction audienceRestriction = new AudienceRestrictionBuilder().buildObject();
		Audience issuerAudience = new AudienceBuilder().buildObject();
		//issuerAudience.setAudienceURI("https://www.okta.com/saml2/service-provider/spkdluteneimsgrqynuj");
		issuerAudience.setAudienceURI("https://www.okta.com/saml2/service-provider/spkdluteneimsgrqynuj");
		audienceRestriction.getAudiences().add(issuerAudience);
		samlAssertion.setSubject(subject1);
		
		//Condition
		Conditions conditions = new ConditionsBuilder().buildObject();
        conditions.setNotBefore(now);
        conditions.setNotOnOrAfter(now.plusMinutes(2));
        conditions.getAudienceRestrictions().add(audienceRestriction);
        samlAssertion.setConditions(conditions);
        
        //Attribute statement
		AttributeStatement attrStatement = new AttributeStatementBuilder().buildObject();
		 int i=0;
       String k[]= {"First Name","Last Name","Email","User Name"};
       if(userAttributes != null){
           Iterator keySet = userAttributes.keySet().iterator();
           while (keySet.hasNext() ){
               String name = keySet.next().toString();
               String val = userAttributes.get(name);
               String refName=k[i];
               i++;
               Attribute attrFirstName=new AttributeBuilder().buildObject();
               XMLObjectBuilder<?> stringBuilder = getSAMLBuilder().getBuilder(XSString.TYPE_NAME);
               XSString stringValue = (XSString) stringBuilder.buildObject(
                       AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME); 
               attrFirstName.setNameFormat(Attribute.UNSPECIFIED);
               attrFirstName.setName(name);
               attrFirstName.setFriendlyName(refName);
               stringValue.setValue(val);
               attrFirstName.getAttributeValues().add(stringValue);
               attrStatement.getAttributes().add(attrFirstName);
           }
       }
		samlAssertion.getAttributeStatements().add(attrStatement);
		
		/*Signature sign=sign(samlAssertion);
		samlAssertion.setSignature(sign);
		((SAMLObjectContentReference)sign.getContentReferences().get(0))
        .setDigestAlgorithm(EncryptionConstants.ALGO_ID_DIGEST_SHA256);
		  try {
		   Configuration.getMarshallerFactory().getMarshaller(samlAssertion)
		     .marshall(samlAssertion);
		  } catch (MarshallingException e) {
		   e.printStackTrace();
		  }

		  try {
		   Signer.signObject(sign);
		  } catch (SignatureException e) {
		   e.printStackTrace();
		  }*/
		return samlAssertion;

	}

	private String generateSAMLResponse(Response response) throws Exception {

		Marshaller marshaller = org.opensaml.Configuration.getMarshallerFactory().getMarshaller(response);
		org.w3c.dom.Element authDOM = marshaller.marshall(response);
		StringWriter rspWrt = new StringWriter();
		XMLHelper.writeNode(authDOM, rspWrt);
		String messageXML = rspWrt.toString();

		String samlResponse = Base64.encodeBytes(messageXML.getBytes(), Base64.DONT_BREAK_LINES);

		System.out.println("SAMLResponse: " + samlResponse);

		// return URLEncoder.encode(samlRequest,"UTF-8");
		return samlResponse;

	}

	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
		System.out.println("tes1");
		//response.sendRedirect("/home.jsp");
		return;
	}

	private AuthnRequest getAuthnRequest(String samlRequest) throws Exception {

		DefaultBootstrap.bootstrap();

		byte[] decoded = Base64.decode(samlRequest);
		ByteArrayInputStream stream = new ByteArrayInputStream(decoded);

		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		DocumentBuilder docBuilder = factory.newDocumentBuilder();
		Document samlDocument = docBuilder.parse(stream);
		Element samlElem = samlDocument.getDocumentElement();

		UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(samlElem);
		Object requestXmlObj = unmarshaller.unmarshall(samlElem);

		AuthnRequest request = (AuthnRequest) requestXmlObj;

		System.out.println("/n/n/n/n/n");

		String acsUrl = request.getAssertionConsumerServiceURL();
		System.out.println("ACS URL: " + acsUrl);
		// result.put("acsUrl",acsUrl);

		String requestId = request.getID();
		System.out.println("Request ID: " + requestId);
		// result.put("requestId",requestId);

		try {
			//SP_ISSUER = request.getIssuer().getDOM().getChildNodes().item(0).getNodeValue();
			System.out.println("ISSUER: " + "https://www.okta.com/saml2/service-provider/spkdluteneimsgrqynu");
			// result.put("issuerId",issuerId);
		} catch (Exception e) {
			System.out.println("Exception " + e);
		}

		System.out.println("AuthnRequest: " + request.toString());
		return request;

	}

	/*private Map<String, String> processSamlRequest(String samlRequest) throws Exception {

		System.out.println("in process samlreq..");
		Map<String, String> result = new HashMap<>();
		byte[] decoded = Base64.decode(samlRequest);
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		DocumentBuilder dBuilder = factory.newDocumentBuilder();
		Document doc = dBuilder.parse(new ByteArrayInputStream(decoded));
		doc.getDocumentElement().normalize();
		Element samlElement = doc.getDocumentElement();
		DefaultBootstrap.bootstrap();
		Unmarshaller unmarshaller = null;
		unmarshaller = org.opensaml.Configuration.getUnmarshallerFactory().getUnmarshaller(samlElement);
		XMLObject obj = unmarshaller.unmarshall(samlElement);
			AuthnRequest request = (AuthnRequest) obj;
		System.out.println("/n/n/n/n/n");
		;
		String acsUrl = request.getAssertionConsumerServiceURL();
		System.out.println("ACS URL: " + acsUrl);
		result.put("acsUrl", acsUrl);

		String requestId = request.getID();
		System.out.println("Request ID: " + requestId);
		result.put("requestId", requestId);

		try {
			String issuerId = request.getIssuer().getDOM().getChildNodes().item(0).getNodeValue();
			System.out.println("ISSUER: " + issuerId);
			result.put("issuerId", issuerId);
		} catch (Exception e) {
			System.out.println("Exception " + e);
		}

		System.out.println("AuthnRequest: " + request.toString());
			Signature sig=new SignatureBuilder().buildObject();
			sig.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		return result;

	}*/
	private static Credential signingCredential = null;
    final static String password = "lib123";
    final static String certificateAliasName = "selfsigned";

    @SuppressWarnings("static-access")
    private Credential intializeCredentials() throws FileNotFoundException {
        KeyStore ks = null;
        char[] password = this.password.toCharArray();
        System.out.println("password is "+ password);
        try {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
            System.out.println("ks is "+ks);
        } catch (KeyStoreException e) {
            System.out.println("Error while Intializing Keystore"+e);
        }

        // Read Keystore
       // InputStream is = getClass().getResourceAsStream("G:\\SAML-Okta\\keystore.jks");
        InputStream is=new FileInputStream("G:\\SAML-Okta\\keystore.jks");
        System.out.println("input stream is "+is);
        // Load KeyStore
        try {
            ks.load(is, password);
        } catch (Exception e) {
        	 System.out.println("Failed to Load the KeyStore:: "+e);
        }


        // Get Private Key Entry From Certificate
        KeyStore.PrivateKeyEntry pkEntry = null;
        try {
            pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(this.certificateAliasName, new KeyStore.PasswordProtection(this.password.toCharArray()));
            System.out.println("pkentery "+pkEntry);
        } catch (Exception e) {
        	 System.out.println("Failed to Get Private Entry From the keystore"+ e);
        }

        PrivateKey pk = pkEntry.getPrivateKey();

        java.security.cert.X509Certificate certificate = (java.security.cert.X509Certificate) pkEntry.getCertificate();
        BasicX509Credential credential = new BasicX509Credential();
        credential.setEntityCertificate(certificate);
        credential.setPrivateKey(pk);
        signingCredential = credential;
       
        System.out.println("Private Key loaded");
        return signingCredential ;

    }
public Signature signResponse(Response response)  {
		
	try {
		intializeCredentials();
	} catch (FileNotFoundException e1) {
		e1.printStackTrace();
	}
	try {
        DefaultBootstrap.bootstrap();
    } catch (ConfigurationException e) {
        System.out.println("Configuration exception");
    }
    Signature signature = (Signature) Configuration
            .getBuilderFactory()
            .getBuilder(Signature.DEFAULT_ELEMENT_NAME)
            .buildObject(Signature.DEFAULT_ELEMENT_NAME);

    signature.setSigningCredential(signingCredential);
    signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
    signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
    SecurityConfiguration secConfig = Configuration.getGlobalSecurityConfiguration();
    try {
        SecurityHelper.prepareSignatureParams(signature, signingCredential, secConfig, null);
    } catch (Exception e) {
        System.out.println("Couldn't prepare signature");
    }
    return signature;
	}
	public Signature sign(Assertion assertion)  {
		
		try {
			intializeCredentials();
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		}
		try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            System.out.println("Configuration exception");
        }
        Signature signature = (Signature) Configuration
                .getBuilderFactory()
                .getBuilder(Signature.DEFAULT_ELEMENT_NAME)
                .buildObject(Signature.DEFAULT_ELEMENT_NAME);

        signature.setSigningCredential(signingCredential);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        SecurityConfiguration secConfig = Configuration.getGlobalSecurityConfiguration();
        try {
            SecurityHelper.prepareSignatureParams(signature, signingCredential, secConfig, null);
        } catch (Exception e) {
            System.out.println("Couldn't prepare signature");
        }
        return signature;
	}

}
