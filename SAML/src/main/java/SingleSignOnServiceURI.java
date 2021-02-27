//package com.slabs.login.controller;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(name="SingleSignOnService",urlPatterns={"/SingleSignOnService"})
public class SingleSignOnServiceURI extends HttpServlet {

    /*private static final String IDP_SSO_URL = "http://localhost:8000/sp/SingleSignOnServiceURI";

    private static final String RELAYSTATE_BASE_URL = "http://localhost:8080/sp/home";

    private static final String ACS_URL = "http://localhost:8080/sp/acs-servlet";

    private static final String ISSUER_ID = "http://mock-idp";

    private LoginService loginService;

    @Override
    public void init() {
        loginService = new LoginServiceImpl();
    }
*/
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
		System.out.println("yes/..");
       //response.sendRedirect("home.jsp");
	   return;
    }

    @Override 
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        System.out.println("yes/ post..");
		return;
    }

}
