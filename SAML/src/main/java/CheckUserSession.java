//package com.saml.sp;
import java.sql.*;
import java.util.*;
import java.sql.DriverManager;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.*;
import javax.servlet.ServletException;
import java.io.PrintWriter;
import java.io.IOException;

@WebServlet("/checkUserSession")

public class CheckUserSession extends HttpServlet {
	protected void doGet(HttpServletRequest request,HttpServletResponse response) throws IOException,ServletException{
		
			HttpSession session=request.getSession();
			String userName=(String) session.getAttribute("username");
			System.out.println("in.......");
			//String AuthnReq=Authn.getAuthReq();
			return;
	}	
}