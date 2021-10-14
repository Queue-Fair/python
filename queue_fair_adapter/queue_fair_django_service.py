from queue_fair_adapter.queue_fair_service import QueueFairService


class QueueFairDjangoService(QueueFairService):

    def __init__(self, request, response):
        self.request = request
        self.response = response
        self.isSecure = request.is_secure()

    def setCookie(self, name, value, lifetimeSeconds, domain):
        # name,value,max_age,expires,path,domain,secure,httponly,samesite
        self.response.set_cookie(name, value, lifetimeSeconds, None, "/",
                                 domain, self.isSecure, False,
                                 "None" if self.isSecure else None)

    def redirect(self, location):
        self.response.status_code = 302
        self.addHeader("Location", location)

    def getCookie(self, name):
        if(name not in self.request.COOKIES):
            return ""
        return self.request.COOKIES[name]

    def addHeader(self, name, value):
        self.response.headers[name] = value
