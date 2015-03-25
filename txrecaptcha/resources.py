# -*- coding: utf-8 ; test-case-name: test_recaptcha -*-
#_____________________________________________________________________________
#
# This file is part of txrecaptcha, a Twisted reCAPTCHA client.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           Matthew Finkel 0x017DD169EA793BE2 <sysrqb@torproject.org>  
# :copyright: (c) 2013-2015, Isis Lovecruft
#             (c) 2013-2015, Matthew Finkel
#             (c) 2013-2015, The Tor Project, Inc.
# :license: see LICENSE file for licensing information
#_____________________________________________________________________________

"""Resources for Twisted-based HTTP(S) servers to serve reCAPTCHAs to clients.
"""

import base64
import ipaddr
import logging
import os

try:
    import mako.exceptions
    from mako.template import Template
    from mako.lookup import TemplateLookup
except ImportError:
    logging.warn(
        ("Could not import Mako template system: https://pypi.python.org/pypi/Mako/ "
         "You will need to override the render_GET() and render_POST methods "
         "for txrecaptcha.resources.CaptchaProtectedResource to use your own "
         "templating system."))

from twisted.web import resource
from twisted.web import server
from twisted.web.util import redirectTo

from txrecaptcha import captcha
from txrecaptcha import recaptcha


TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')
logging.debug("Set template root to %s" % TEMPLATE_DIR)

# Setting `filesystem_checks` to False is recommended for production servers,
# due to potential speed increases. This means that the atimes of the Mako
# template files aren't rechecked every time the template is requested
# (otherwise, if they are checked, and the atime is newer, the template is
# recompiled). `collection_size` sets the number of compiled templates which
# are cached before the least recently used ones are removed. See:
# http://docs.makotemplates.org/en/latest/usage.html#using-templatelookup
lookup = TemplateLookup(directories=[TEMPLATE_DIR],
                        output_encoding='utf-8',
                        filesystem_checks=False,
                        collection_size=500)


def replaceErrorPage(error, template_name=None):
    """Create a general error page for displaying in place of tracebacks.

    Log the error to BridgeDB's logger, and then display a very plain "Sorry!
    Something went wrong!" page to the client.

    :type error: :exc:`Exception`
    :param error: Any exeption which has occurred while attempting to retrieve
                  a template, render a page, or retrieve a resource.
    :param str template_name: A string describing which template/page/resource
                              was being used when the exception occurred,
                              i.e. ``'index.html'``.
    :returns: A string containing HTML to serve to the client (rather than
              serving a traceback).
    """
    logging.error("Error while attempting to render %s: %s"
                  % (template_name or 'template',
                     mako.exceptions.text_error_template().render()))
    errmsg = _("Sorry! Something went wrong with your request.")
    rendered = "<html><head></head><body><p>{0}</p></body></html>".format(errmsg)

    return rendered


class CaptchaProtectedResource(resource.Resource):
    """A general resource protected by some form of CAPTCHA."""

    isLeaf = True

    def __init__(self, publicKey=None, secretKey=None,
                 useForwardedHeader=False, protectedResource=None):
        resource.Resource.__init__(self)
        self.publicKey = publicKey
        self.secretKey = secretKey
        self.useForwardedHeader = useForwardedHeader
        self.resource = protectedResource

    def getClientIP(self, request):
        """Get the client's IP address from the :header:`X-Forwarded-For`
        header, or from the :api:`request <twisted.web.server.Request>`.

        :rtype: None or str
        :returns: The client's IP address, if it was obtainable.
        """
        ip = None
        if self.useForwardedHeader:
            header = request.getHeader("X-Forwarded-For")
            if header:
                ip = header.split(",")[-1].strip()
                try:
                    ipaddr.IPAddress(ip)
                except ValueError:
                    logging.warn("Got weird X-Forwarded-For value %r" % header)
                    ip = None
        else:
            ip = request.getClientIP()
        return ip

    def getCaptchaImage(self, request=None):
        """Get a CAPTCHA image.

        :returns: A 2-tuple of ``(image, challenge)``, where ``image`` is a
                  binary, JPEG-encoded image, and ``challenge`` is a unique
                  string. If unable to retrieve a CAPTCHA, returns a tuple
                  containing two empty strings.
        """
        return ('', '')

    def extractClientSolution(self, request):
        """Extract the client's CAPTCHA solution from a POST request.

        This is used after receiving a POST request from a client (which
        should contain their solution to the CAPTCHA), to extract the solution
        and challenge strings.

        :type request: :api:`twisted.web.http.Request`
        :param request: A ``Request`` object for 'bridges.html'.
        :returns: A redirect for a request for a new CAPTCHA if there was a
            problem. Otherwise, returns a 2-tuple of strings, the first is the
            client's CAPTCHA solution from the text input area, and the second
            is the challenge string.
        """
        try:
            challenge = request.args['captcha_challenge_field'][0]
            response = request.args['captcha_response_field'][0]
        except Exception:  # pragma: no cover
            return redirectTo(request.URLPath(), request)
        return (challenge, response)

    def checkSolution(self, request):
        """Override this method to check a client's CAPTCHA solution.

        :rtype: bool
        :returns: ``True`` if the client correctly solved the CAPTCHA;
            ``False`` otherwise.
        """
        return False

    def render_GET(self, request):
        """Retrieve a ReCaptcha from the API server and serve it to the client.

        :type request: :api:`twisted.web.http.Request`
        :param request: A ``Request`` object for a page which should be
            protected by a CAPTCHA.
        :rtype: str
        :returns: A rendered HTML page containing a ReCaptcha challenge image
            for the client to solve.
        """
        rtl = False
        image, challenge = self.getCaptchaImage(request)

        try:
            # TODO: this does not work for versions of IE < 8.0
            imgstr = 'data:image/jpeg;base64,%s' % base64.b64encode(image)
            template = lookup.get_template('captcha.html')
            rendered = template.render(strings,
                                       imgstr=imgstr,
                                       challenge_field=challenge)
        except Exception as err:
            rendered = replaceErrorPage(err, 'captcha.html')

        request.setHeader("Content-Type", "text/html; charset=utf-8")
        return rendered

    def render_POST(self, request):
        """Process a client's CAPTCHA solution.

        If the client's CAPTCHA solution is valid (according to
        :meth:`checkSolution`), process and serve their original
        request. Otherwise, redirect them back to a new CAPTCHA page.

        :type request: :api:`twisted.web.http.Request`
        :param request: A ``Request`` object, including POST arguments which
            should include two key/value pairs: one key being
            ``'captcha_challenge_field'``, and the other,
            ``'captcha_response_field'``. These POST arguments should be
            obtained from :meth:`render_GET`.
        :rtype: str
        :returns: A rendered HTML page containing a ReCaptcha challenge image
            for the client to solve.
        """
        request.setHeader("Content-Type", "text/html; charset=utf-8")

        if self.checkSolution(request) is True:
            try:
                rendered = self.resource.render(request)
            except Exception as err:
                rendered = replaceErrorPage(err)
            return rendered

        logging.debug("Client failed a CAPTCHA; returning redirect to %s"
                      % request.uri)
        return redirectTo(request.uri, request)


class ReCaptchaProtectedResource(CaptchaProtectedResource):
    """A web resource which uses the reCaptcha_ service.

    .. _reCaptcha: http://www.google.com/recaptcha
    """

    def __init__(self, remoteIP=None, **kwargs):
        """Create a resouce which protects another with a reCAPTCHA.

        :param str remoteIP: The IP address to report to the reCAPTCHA API
            server. Normally, this would be the client's IP address from the
            request; however, lying is not only acceptable but (for privacy
            reasons) encouraged.
        """
        CaptchaProtectedResource.__init__(self, **kwargs)
        self.remoteIP = remoteIP

    def _renderDeferred(self, checkedRequest):
        """Render this resource asynchronously.

        :type checkedRequest: tuple
        :param checkedRequest: A tuple of ``(bool, request)``, as returned
            from :meth:`checkSolution`.
        """
        try:
            valid, request = checkedRequest
        except Exception as err:
            logging.error("Error in _renderDeferred(): %s" % err)
            return

        logging.debug("Attemping to render %svalid request %r"
                      % ('' if valid else 'in', request))
        if valid is True:
            try:
                rendered = self.resource.render(request)
            except Exception as err:  # pragma: no cover
                rendered = replaceErrorPage(err)
        else:
            logging.info("Client failed a CAPTCHA; redirecting to %s"
                         % request.uri)
            rendered = redirectTo(request.uri, request)

        try:
            request.write(rendered)
            request.finish()
        except Exception as err:  # pragma: no cover
            logging.exception(err)

        return request

    def getCaptchaImage(self, request):
        """Get a CAPTCHA image from the remote reCaptcha server.

        :type request: :api:`twisted.web.http.Request`
        :param request: A client's initial request for some other resource
            which is protected by this one (i.e. protected by a CAPTCHA).
        :returns: A 2-tuple of ``(image, challenge)``, where::
            - ``image`` is a string holding a binary, JPEG-encoded image.
            - ``challenge`` is a unique string associated with the request.
        """
        capt = captcha.ReCaptcha(self.publicKey, self.secretKey)

        try:
            capt.get()
        except Exception as error:
            logging.fatal("Connection to Recaptcha server failed: %s" % error)

        if capt.image is None:
            logging.warn("No CAPTCHA image received from ReCaptcha server!")

        return (capt.image, capt.challenge)

    def getRemoteIP(self):
        """Mask the client's real IP address with a faked one.

        The fake client IP address is sent to the reCaptcha server, and it is
        either the public IP address of bridges.torproject.org (if the config
        option ``RECAPTCHA_REMOTE_IP`` is configured), or a random IP.

        :rtype: str
        :returns: A fake IP address to report to the reCaptcha API server.
        """
        if self.remoteIP:
            remoteIP = self.remoteIP
        else:
            # generate a random IP for the captcha submission
            remoteIP = ipaddr.IPv4Address(random.randint(0, 2**32-1)).compressed

        return remoteIP

    def checkSolution(self, request):
        """Process a solved CAPTCHA by sending it to the ReCaptcha server.

        The client's IP address is not sent to the ReCaptcha server; instead,
        a completely random IP is generated and sent instead.

        :type request: :api:`twisted.web.http.Request`
        :param request: A ``Request`` object, including POST arguments which
            should include two key/value pairs: one key being
            ``'captcha_challenge_field'``, and the other,
            ``'captcha_response_field'``. These POST arguments should be
            obtained from :meth:`render_GET`.
        :rtupe: :api:`twisted.internet.defer.Deferred`
        :returns: A deferred which will callback with a tuple in the following
            form:
                (:type:`bool`, :api:`twisted.web.server.Request`)
            If the CAPTCHA solution was valid, a tuple will contain::
                (True, Request)
            Otherwise, it will contain::
                (False, Request)
        """
        challenge, response = self.extractClientSolution(request)
        clientIP = self.getClientIP(request)
        remoteIP = self.getRemoteIP()

        logging.debug("Captcha from %r. Parameters: %r"
                      % (clientIP, request.args))

        def checkResponse(solution, request):
            """Check the :class:`txrecaptcha.RecaptchaResponse`.

            :type solution: :class:`txrecaptcha.RecaptchaResponse`.
            :param solution: The client's CAPTCHA solution, after it has been
                submitted to the reCaptcha API server.
            """
            # This valid CAPTCHA result from this function cannot be reliably
            # unittested, because it's callbacked to from the deferred
            # returned by ``txrecaptcha.submit``, the latter of which would
            # require networking (as well as automated CAPTCHA
            # breaking). Hence, the 'no cover' pragma.
            if solution.is_valid:  # pragma: no cover
                logging.info("Valid CAPTCHA solution from %r." % clientIP)
                return (True, request)
            else:
                logging.info("Invalid CAPTCHA solution from %r: %r"
                             % (clientIP, solution.error_code))
                return (False, request)

        d = recaptcha.submit(challenge, response, self.secretKey,
                             remoteIP).addCallback(checkResponse, request)
        return d

    def render_GET(self, request):
        """Retrieve a ReCaptcha from the API server and serve it to the client.

        :type request: :api:`twisted.web.http.Request`
        :param request: A ``Request`` object for 'bridges.html'.
        :rtype: str
        :returns: A rendered HTML page containing a ReCaptcha challenge image
            for the client to solve.
        """
        return CaptchaProtectedResource.render_GET(self, request)

    def render_POST(self, request):
        """Process a client's CAPTCHA solution.

        If the client's CAPTCHA solution is valid (according to
        :meth:`checkSolution`), process and serve their original
        request. Otherwise, redirect them back to a new CAPTCHA page.

        :type request: :api:`twisted.web.http.Request`
        :param request: A ``Request`` object, including POST arguments which
            should include two key/value pairs: one key being
            ``'captcha_challenge_field'``, and the other,
            ``'captcha_response_field'``. These POST arguments should be
            obtained from :meth:`render_GET`.
        :returns: :api:`twisted.web.server.NOT_DONE_YET`, in order to handle
            the ``Deferred`` returned from :meth:`checkSolution`. Eventually,
            when the ``Deferred`` request is done being processed,
            :meth:`_renderDeferred` will handle rendering and displaying the
            HTML to the client.
        """
        d = self.checkSolution(request)
        d.addCallback(self._renderDeferred)
        return server.NOT_DONE_YET
