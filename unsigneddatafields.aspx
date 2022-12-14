<%@ Page Language="C#" AutoEventWireup="true" CodeFile="unsigneddatafields.aspx.cs" Inherits="secureacceptance.WebForm1" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
<head>
    <title>Unsigned Data Fields</title>
    <link rel="stylesheet" type="text/css" href="Styles/payment.css"/>
</head>
<body>
<form id="payment_confirmation" action=" https://testsecureacceptance.cybersource.com/silent/token/create" method="post"/>
<fieldset id="confirmation">
    <legend>Signed Data Fields</legend>
These fields have been signed on your server, and a signature has been generated.  This will <br> detect tampering with these values as they pass through the consumers browser to the SASOP endpoint.<BR></BR>
    <div>
        <%
            foreach (var key in Request.Form.AllKeys)
            { 
                Response.Write("<div>");
                Response.Write("<span class=\"fieldName\">" + key + ":</span><span class=\"fieldValue\">" + Request.Params[key] + "</span>");
                Response.Write("</div>");
            }
        %>
    </div>
</fieldset>
    <%
        IDictionary<string, string> parameters = new Dictionary<string, string>();
        foreach (var key in Request.Form.AllKeys)
        {
            Response.Write("<input type=\"hidden\" id=\"" + key + "\" name=\"" + key + "\" value=\"" + Request.Params[key] + "\"/>\n");
            parameters.Add(key, Request.Params[key]);
        }
        Response.Write("<input type=\"hidden\" id=\"signature\" name=\"signature\" value=\"" + secureacceptance.Security.sign(parameters) + "\"/>\n");
    %>
    <fieldset>
        <legend>Unsigned Data Fields</legend>  
        Card data fields are posted directly to CyberSource, together with the fields above.  These field <br>
        names will need to be included in the unsigned_field_names.
        <BR></BR>
        <div id="UnsignedDataSection" class="section">
        <span>card_type:</span><input type="text" name="card_type"><br/>
        <span>card_number:</span><input type="text" name="card_number"><br/>
        <span>card_expiry_date:</span><input type="text" name="card_expiry_date"><br/>
	</div>
    </fieldset>
  <input type="submit" id="submit" value="Confirm "/>
  <script type="text/javascript" src="Scripts/jquery-1.7.min.js"></script>
  <script type="text/javascript" src="Scripts/payment_form.js"></script>

</form>
</body>
</html>
