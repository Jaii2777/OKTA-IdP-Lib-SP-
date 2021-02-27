//package com.slabs.login.controller;

import java.sql.*;
import java.util.*;
import java.sql.DriverManager;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.*;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import org.opensaml.xml.util.Base64;

import java.io.PrintWriter;
import java.io.ByteArrayInputStream;
import java.io.IOException;

@WebServlet(name = "/SSO", urlPatterns = { "/SSO" })
public class SSO extends HttpServlet {

	private static Map<String, String> currentRequests;

	@Override
	public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
		System.out.println("tes");

		// System.out.println("okta request
		// is"+coyoteRequest.getParameters().getParameter(name));
		String samlRequest = (String) request.getParameter("SAMLRequest");
		String relayState= (String) request.getParameter("RelayState");
		System.out.println("okta request is" + samlRequest);

		System.out.println("okta relaaystate is" + relayState);
		request.setAttribute("SAMLRequest", samlRequest);
		request.setAttribute("RelayState", relayState);
		RequestDispatcher dispatcher = request.getServletContext().getRequestDispatcher("/AppLogin.jsp");
		dispatcher.forward(request, response);

		
	}

	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
		System.out.println("tes1");
		response.sendRedirect("/home.jsp");
		return;
	}

	
	
	private Map<String,String> processSamlRequest(String samlRequest) throws Exception {

		Map<String,String> result = new HashMap<>();

		byte[] decoded = Base64.decode(samlRequest);

		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder dBuilder = factory.newDocumentBuilder();
        Document doc = dBuilder.parse(new ByteArrayInputStream(decoded));
        doc.getDocumentElement().normalize();

        Element samlElement = doc.getDocumentElement();

        // UnmarshallerFactory
        // umFactory=XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
        // Unmarshaller unmarshaller=umFactory.getUnmarshaller(samlElement);
        DefaultBootstrap.bootstrap();
        Unmarshaller unmarshaller = null;

        // System.out.println("UNMARSHALLERS " +
        // org.opensaml.Configuration.getUnmarshallerFactory().getUnmarshallers().toString());
        unmarshaller = org.opensaml.Configuration.getUnmarshallerFactory().getUnmarshaller(samlElement);
       	XMLObject obj = unmarshaller.unmarshall(samlElement);
		AuthnRequest request = (AuthnRequest) obj;
		String acsUrl = request.getAssertionConsumerServiceURL();
		System.out.println("ACS URL: " + acsUrl);
		result.put("acsUrl",acsUrl);

		String requestId = request.getID();
		System.out.println("Request ID: " + requestId);
		result.put("requestId",requestId);

		try {
			String issuerId = request.getIssuer().getDOM().getChildNodes().item(0).getNodeValue();
			System.out.println("ISSUER: " + issuerId);
			result.put("issuerId",issuerId);
		} catch (Exception e) {
			System.out.println("Exception " + e);
		}

		System.out.println("AuthnRequest: " + request.toString());

		return result;

	}
}
