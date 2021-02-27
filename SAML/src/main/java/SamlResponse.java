import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.impl.ResponseBuilder;

public class SamlResponse {

	//static String ISSUER_ID="0oa8afzkun589XwAm5d6";
	
	static String genSamlResponse(String mailId) {
		System.out.println("in....");
		String baseEncodeResp=createResponse(mailId);
		return baseEncodeResp;
	}
	 static String createResponse(String mailId){
	System.out.println("in....1");
	ResponseBuilder responseBuilder=new ResponseBuilder();
    Response samlResponse = responseBuilder.buildObject();
	System.out.println("in....2");
   /* samlResponse.setIssueInstant("k");
    samlResponse.setVersion("2.0");
    samlResponse.setID("123");
    samlResponse.setInResponseTo(" ");
    samlResponse.setIssuer(issuer);
    samlResponse.setStatus(status);
    samlResponse.setSignature(signature);
    if(assertions.size() >0){
      for (Assertion assertion : assertions) {
        saml2Response.getAssertions().add(assertion);
      }
    }
    return saml2Response;
  }
	}*/
		System.out.println("in....3");
			IssuerBuilder issuerBuilder = new IssuerBuilder(); 
			Issuer issuer = issuerBuilder.buildObject(); 
			issuer.setValue("0oa8afzkun589XwAm5d6");
			
			samlResponse.setIssuer(issuer);
			samlResponse.setIssueInstant(new DateTime());
			samlResponse.setDestination("https://dev-43055720.okta.com/sso/saml2/0oa8afzkun589XwAm5d6");
			//samlResponse.setStatus(status);
			samlResponse.setInResponseTo("https://www.okta.com/saml2/service-provider/spkdluteneimsgrqynuj");
			System.out.println(samlResponse);
			return "ok";
	}
	}