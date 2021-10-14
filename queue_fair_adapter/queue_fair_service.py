class QueueFairService:

    # Set a cookie - see QueueFairDjangoService for additional cookie fields.
    def setCookie(self, name, value, lifetimeSeconds, domain):
        pass

    # Do a 302 Redirect with a Location: header
    def redirect(self, location):
        pass

    # Return the cookie value if found, or '' if it does not exist
    def getCookie(self, name):
        pass

    # Add a header to the HTTP response
    def addHeader(self, name, value):
        pass
