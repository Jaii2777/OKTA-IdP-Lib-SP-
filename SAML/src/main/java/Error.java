//package com.slabs.login.controller;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(name="err",urlPatterns={"/err"})
public class Error extends HttpServlet {

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
		System.out.println("error/..");
       response.sendRedirect("home.jsp");
	   return;
    }

    @Override 
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        System.out.println("yes/ post..");
		return;
    }

}
