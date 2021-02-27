<html>
    <body>
         <form enctype="application/x-www-form-urlencoded" id="hidden-form" action="https://dev-43055720.okta.com/sso/saml2/0oa8afzkun589XwAm5d6" method="POST"> 
        	<!--  <form enctype="application/x-www-form-urlencoded" id="hidden-form" action="https://dev-95150911.okta.com/sso/saml2/0oa9oidiojQI8wKwM5d6" method="POST">-->
            <input type="text" name="SAMLResponse" value="${SAMLResponse}" style="display:block">
            <input type="text" name="RelayState" value="${RelayState}" style="display:block">
        </form>
        <script>
            var elem = document.getElementById("hidden-form");
            //elem.enctype = "text/plain";
            elem.submit();
        </script>
    </body>
</html>