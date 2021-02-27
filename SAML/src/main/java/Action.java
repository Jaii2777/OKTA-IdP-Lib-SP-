import java.io.*;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.HashMap;
import java.util.Map;
public class Action {
	
	static  Connection getConnection()  {
      Connection con = null;
      try {
         con = DriverManager.getConnection ("jdbc:mysql://localhost/library","root", "root");
      } 
      catch (Exception e) {
         e.printStackTrace();
      }
      return con;
   }
   
	static Map<String,String> getUserAttributes(String mailId) {
		 Connection con = null;
	      ResultSet rs = null;
	      PreparedStatement stmt = null;
	      Map<String,String> ans=new HashMap<>();
	      try {
	          con = getConnection();
			  String sql = "select * from okta_users where mailId=?";
	          stmt = con.prepareStatement(sql);
	          stmt.setString(1, mailId);
	          rs = stmt.executeQuery();
	    
	          if (rs.next()) { 
					ans.put("firstName", rs.getString("firstname"));
					ans.put("lastName", rs.getString("lastname"));
					ans.put("email", rs.getString("mailId"));
					rs.close();
					stmt.close();
					con.close();
			  }
				else{
					rs.close();
					stmt.close();
					con.close();
				}
	       } catch (Exception e) {
	           e.printStackTrace();
	       }
		   return ans;
	       }
   static String isValidUser(String mailId,String password) {
	 Connection con = null;
      ResultSet rs = null;
      PreparedStatement stmt = null;
      try {
          con = getConnection();
		  String sql = "select mailId from okta_users where mailId=?  and password=?";
		 // System.out.println(mailId+" "+password);
          stmt = con.prepareStatement(sql);
          stmt.setString(1, mailId);
          stmt.setString(2, password);
          rs = stmt.executeQuery();
    
          if (rs.next()) { 
				rs.close();
				stmt.close();
				con.close();
				return "valid";
		  }
			else{
				rs.close();
				stmt.close();
				con.close();
				return "invalid";
			}
       } catch (Exception e) {
           e.printStackTrace();
       }
	   return " ";
       }
}