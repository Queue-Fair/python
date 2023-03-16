from django.shortcuts import render
from django.http import HttpResponse
from queue_fair_adapter.queue_fair_adapter import QueueFairAdapter
from queue_fair_adapter.queue_fair_config import QueueFairConfig
from queue_fair_adapter.queue_fair_django_service import QueueFairDjangoService

import django


# Convenience method to call from your own view methods.
def checkQueueFair(request, response):
    try:
        # Encapsulates Django for use with the Adapter
        adapterService = QueueFairDjangoService(request, response)

        # If you are not using Django, or your Django is behind a CDN or proxy,
        # you may need to modify these property sets. The requestedURL
        # MUST contain the query string (GET parameters) if present.
        requestedURL = request.build_absolute_uri()
        userAgent = request.META["HTTP_USER_AGENT"]
        remoteIPAddress = request.META['REMOTE_ADDR']

        # Enables debug level logging. Comment out for production.
        QueueFairConfig.DEBUG = True

        # The following values must be replaced with the values shown on the
        # Account -> Your Account page in the Portal.
        QueueFairConfig.ACCOUNT = "YOUR_ACCOUNT_SYSTEM_NAME"
        QueueFairConfig.ACCOUNT_SECRET = "YOUR_ACCOUNT_SECRET"

        #Must be writable, readable and executable
        QueueFairConfig.SETTINGS_FILE_CACHE_LOCATION = "."

        adapter = QueueFairAdapter(adapterService, requestedURL,
                                   userAgent, remoteIPAddress, None)

        """
        # If you ONLY want to validate a cookie (Hybrid Security Model)
        # uncomment this section and use this:
        if(requestedURL.find("/app/") != -1):
            passedLifetimeMinutes = 60  # One hour
            queueName = "YOUR_QUEUE_NAME"
            queueSecret = "YOUR_QUEUE_SECRET"
            cookie = adapterService.getCookie(
                QueueFairAdapter.COOKIE_NAME_BASE +
                queueName)
            if not adapter.validateCookie(queueSecret,
                                          passedLifetimeMinutes,
                                          cookie):
                adapter.redirect("https://" + QueueFairConfig.ACCOUNT +
                                 ".queue-fair.net/" + queueName +
                                 "?qfError=InvalidCookie", 0)
                return False

        return True
        """

        # Otherwise, to run the full adapter process, use this:
        if(not adapter.isContinue()):
            return False

        # Page will run.
    except Exception as exc:
        # In case of exception running the adapter,
        # the rest of the page should run
        print("Exception!")
        print(exc)
    return True


def index(request):
    response = HttpResponse()

    if not checkQueueFair(request, response):
        return response

    # Rest of page execution continues.  You MUST use the
    # same HttpResponse object that you passed to checkQueueFair
    # otherwise cookies will not be set.
    response.write("This is protected content")
    return response

