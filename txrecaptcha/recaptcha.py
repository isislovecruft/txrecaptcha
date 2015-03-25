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

"""Twisted-based reCAPTCHA client.

This client *always* uses TLS with strict hostname checking, unlike the
official Google Python recaptcha-client_, which is harcoded_ to use plaintext
HTTP.

Small portions of this code were taken from the official Google Python
recaptcha-client_ module, version 1.0.6.  Those portions are
:class:`RecaptchaResponse`, :data:`API_SERVER`, They total 5 lines of code,
which are copyright the authors of the recaptcha-client_ package.

.. _hardcoded: https://code.google.com/p/recaptcha/source/browse/trunk/recaptcha-plugins/python/recaptcha/client/captcha.py#76
.. _recaptcha-client: https://pypi.python.org/pypi/recaptcha-client/1.0.6
"""

import logging
import urllib

from OpenSSL.crypto import FILETYPE_PEM
from OpenSSL.crypto import load_certificate

from twisted import version as _twistedversion
from twisted.internet import defer
from twisted.internet import protocol
from twisted.internet import reactor
from twisted.python import failure
from twisted.python.versions import Version
from twisted.web import client
from twisted.web.http_headers import Headers
from twisted.web.iweb import IBodyProducer

from zope.interface import implements

from txrecaptcha.crypto import SSLVerifyingContextFactory

#: This was taken from  recaptcha.client.captcha.API_SSL_SERVER.
API_SSL_SERVER = API_SERVER = "https://www.google.com/recaptcha/api"
API_SSL_VERIFY_URL = "%s/verify" % API_SSL_SERVER

#: (type: `OpenSSL.crypto.X509`) Only trust certificate for the reCAPTCHA
#: :data:`API_SSL_SERVER` which were signed by the Google Internet Authority CA.
GOOGLE_INTERNET_AUTHORITY_CA_CERT = load_certificate(FILETYPE_PEM, bytes("""\
-----BEGIN CERTIFICATE-----
MIICsDCCAhmgAwIBAgIDFXfhMA0GCSqGSIb3DQEBBQUAME4xCzAJBgNVBAYTAlVT
MRAwDgYDVQQKEwdFcXVpZmF4MS0wKwYDVQQLEyRFcXVpZmF4IFNlY3VyZSBDZXJ0
aWZpY2F0ZSBBdXRob3JpdHkwHhcNMTIxMjEyMTU1ODUwWhcNMTMxMjMxMTU1ODUw
WjBGMQswCQYDVQQGEwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzEiMCAGA1UEAxMZ
R29vZ2xlIEludGVybmV0IEF1dGhvcml0eTCBnzANBgkqhkiG9w0BAQEFAAOBjQAw
gYkCgYEAye23pIucV+eEPkB9hPSP0XFjU5nneXQUr0SZMyCSjXvlKAy6rWxJfoNf
NFlOCnowzdDXxFdF7dWq1nMmzq0yE7jXDx07393cCDaob1FEm8rWIFJztyaHNWrb
qeXUWaUr/GcZOfqTGBhs3t0lig4zFEfC7wFQeeT9adGnwKziV28CAwEAAaOBozCB
oDAfBgNVHSMEGDAWgBRI5mj5K9KylddH2CMgEE8zmJCf1DAdBgNVHQ4EFgQUv8Aw
6/VDET5nup6R+/xq2uNrEiQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8E
BAMCAQYwOgYDVR0fBDMwMTAvoC2gK4YpaHR0cDovL2NybC5nZW90cnVzdC5jb20v
Y3Jscy9zZWN1cmVjYS5jcmwwDQYJKoZIhvcNAQEFBQADgYEAvprjecFG+iJsxzEF
ZUNgujFQodUovxOWZshcnDW7fZ7mTlk3zpeVJrGPZzhaDhvuJjIfKqHweFB7gwB+
ARlIjNvrPq86fpVg0NOTawALkSqOUMl3MynBQO+spR7EHcRbADQ/JemfTEh2Ycfl
vZqhEFBfurZkX0eTANq98ZvVfpg=
-----END CERTIFICATE-----"""))

# `t.w.client.HTTPConnectionPool` isn't available in Twisted-12.0.0
# (see ticket #11219: https://bugs.torproject.org/11219):
_connectionPoolAvailable = _twistedversion >= Version('twisted', 12, 1, 0)
if _connectionPoolAvailable:
    logging.info("Using HTTPConnectionPool for reCaptcha API server.")
    _pool = client.HTTPConnectionPool(reactor, persistent=False)
    _pool.maxPersistentPerHost = 5
    _pool.cachedConnectionTimeout = 30
    _agent = client.Agent(reactor, pool=_pool)
else:
    logging.warn("Twisted-%s is too old for HTTPConnectionPool! Disabling..."
                 % _twistedversion.short())
    _pool = None
    _agent = client.Agent(reactor)


# Twisted>=14.0.0 changed the way in which hostname verification works.
if _twistedversion >= Version('twisted', 14, 0, 0):
    from twisted.internet._sslverify import OpenSSLCertificateAuthorities

    class RecaptchaOpenSSLCertificateAuthorities(OpenSSLCertificateAuthorities):
        """The trusted CAs for connecting to reCAPTCHA servers."""
        #: A list of `OpenSSL.crypto.X509` objects.
        caCerts = [GOOGLE_INTERNET_AUTHORITY_CA_CERT,]
        def __init__(self):
            super(RecaptchaOpenSSLCertificateAuthorities, self).__init__(self.caCerts)

    class RecaptchaPolicyForHTTPS(client.BrowserLikePolicyForHTTPS):
        _trustRoot = RecaptchaOpenSSLCertificateAuthorities()
        def __init__(self):
            super(RecaptchaPolicyForHTTPS, self).__init__(trustRoot=self._trustRoot)


def _setAgent(agent):
    """Set the global :attr:`agent`.

    :param agent: An :api:`twisted.web.client.Agent` for issuing requests.
    """
    global _agent
    _agent = agent

def _getAgent(reactor=reactor, url=API_SSL_VERIFY_URL, connectTimeout=30,
              **kwargs):
    """Create a :api:`twisted.web.client.Agent` which will verify the
    certificate chain and hostname for the given **url**.

    :param reactor: A provider of the
        :api:`twisted.internet.interface.IReactorTCP` interface.
    :param str url: The full URL which will be requested with the
        ``Agent``. (default: :attr:`API_SSL_VERIFY_URL`)
    :param pool: An :api:`twisted.web.client.HTTPConnectionPool`
        instance. (default: :attr:`_pool`)
    :type connectTimeout: None or int
    :param connectTimeout: If not ``None``, the timeout passed to
        :api:`twisted.internet.reactor.connectTCP` or
        :api:`twisted.internet.reactor.connectSSL` for specifying the
        connection timeout. (default: ``30``)
    """
    # Twisted>=14.0.0 changed the way in which hostname verification works.
    if _twistedversion >= Version('twisted', 14, 0, 0):
        contextFactory = RecaptchaPolicyForHTTPS()
    else:
        contextFactory = SSLVerifyingContextFactory(url)

    if _connectionPoolAvailable:
        return client.Agent(reactor,
                            contextFactory=contextFactory,
                            connectTimeout=connectTimeout,
                            pool=_pool,
                            **kwargs)
    else:
        return client.Agent(reactor,
                            contextFactory=contextFactory,
                            connectTimeout=connectTimeout,
                            **kwargs)

_setAgent(_getAgent())


class RecaptchaResponseError(ValueError):
    """There was an error with the reCaptcha API server's response."""


class RecaptchaResponse(object):
    """Taken from recaptcha.client.captcha.`RecaptchaResponse`_.
    .. RecaptchaResponse: https://code.google.com/p/recaptcha/source/browse/trunk/recaptcha-plugins/python/recaptcha/client/captcha.py#7
    """
    def __init__(self, is_valid, error_code=None):
        self.is_valid = is_valid
        self.error_code = error_code


class RecaptchaResponseProtocol(protocol.Protocol):
    """HTML parser which creates a :class:`RecaptchaResponse` from the body of
    the reCaptcha API server's response.
    """
    def __init__(self, finished):
        """Create a protocol for creating :class:`RecaptchaResponse`s.

        :type finished: :api:`~twisted.internet.defer.Deferred`
        :param finished: A deferred which will have its ``callback()`` called
             with a :class:`RecaptchaResponse`.
        """
        self.finished = finished
        self.remaining = 1024 * 10
        self.response = ''

    def dataReceived(self, data):
        """Called when some data is received from the connection."""
        if self.remaining:
            received = data[:self.remaining]
            self.response += received
            self.remaining -= len(received)

    def connectionLost(self, reason):
        """Called when the connection was closed.

        :type reason: :api:`twisted.python.failure.Failure`
        :param reason: A string explaning why the connection was closed,
            wrapped in a ``Failure`` instance.

        :raises: A :api:`twisted.internet.error.ConnectError` if the 
        """
        valid = False
        error = reason.getErrorMessage()
        try:
            (valid, error) = self.response.strip().split('\n', 1)
        except ValueError:
            error = "Couldn't parse response from reCaptcha API server"

        valid = bool(valid == "true")
        result = RecaptchaResponse(is_valid=valid, error_code=error)
        logging.debug(
            "ReCaptcha API server response: %s(is_valid=%s, error_code=%s)"
            % (result.__class__.__name__, valid, error))
        self.finished.callback(result)


class _BodyProducer(object):
    """I write a string into the HTML body of an open request."""
    implements(IBodyProducer)

    def __init__(self, body):
        self.body = body
        self.length = len(body)

    def startProducing(self, consumer):
        """Start writing the HTML body."""
        consumer.write(self.body)
        return defer.succeed(None)

    def pauseProducing(self):
        pass

    def stopProducing(self):
        pass

    def resumeProducing(self):
        pass


def _cbRequest(response):
    """Callback for a :api:`twisted.web.client.Agent.request` which delivers
    the result to a :class:`RecaptchaResponseProtocol`.

    :returns: A :api:`~twisted.internet.defer.Deferred` which will callback
    with a ``recaptcha.RecaptchaResponse`` for the request.
    """
    finished = defer.Deferred()
    response.deliverBody(RecaptchaResponseProtocol(finished))
    return finished

def _ebRequest(fail):
    """Errback for a :api:`twisted.web.client.Agent.request`.

    :param fail: A :api:`twisted.python.failure.Failure` which occurred during
        the request.
    """
    logging.debug("txrecaptcha._ebRequest() called with %r" % fail)
    error = fail.getErrorMessage() or "possible problem in _ebRequest()"
    return RecaptchaResponse(is_valid=False, error_code=error)

def _encodeIfNecessary(string):
    """Encode unicode objects in utf-8 if necessary."""
    if isinstance(string, unicode):
        return string.encode('utf-8')
    return string

def submit(recaptcha_challenge_field, recaptcha_response_field,
           private_key, remoteip, agent=_agent):
    """Submits a reCaptcha request for verification. This function is a patched
    version of the ``recaptcha.client.captcha.submit()`` function in
    reCaptcha's Python API.

    It does two things differently:
        1. It uses Twisted for everything.
        2. It uses SSL/TLS for everything.

    This function returns a :api:`~twisted.internet.defer.Deferred`. If you
    need a ``recaptcha.client.captcha.RecaptchaResponse`` to be returned, use
    the :func:`submit` function, which is an ``@inlineCallbacks`` wrapper for
    this function.

    :param str recaptcha_challenge_field: The value of the HTTP POST
        ``recaptcha_challenge_field`` argument from the form.
    :param recaptcha_response_field: The value of the HTTP POST
        ``recaptcha_response_field`` argument from the form.
    :param private_key: The reCAPTCHA API private key.
    :param remoteip: An IP address to give to the reCaptcha API server.
    :returns: A :api:`~twisted.internet.defer.Deferred` which will callback
        with a ``recaptcha.RecaptchaResponse`` for the request.
    """
    if not (recaptcha_response_field and len(recaptcha_response_field) and
            recaptcha_challenge_field and len(recaptcha_challenge_field)):
        d = defer.Deferred()
        d.addBoth(_ebRequest)  # We want `is_valid=False`
        d.errback(failure.Failure(ValueError('incorrect-captcha-sol')))
        return d

    params = urllib.urlencode({
        'privatekey': _encodeIfNecessary(private_key),
        'remoteip':   _encodeIfNecessary(remoteip),
        'challenge':  _encodeIfNecessary(recaptcha_challenge_field),
        'response':   _encodeIfNecessary(recaptcha_response_field)})
    body = _BodyProducer(params)
    headers = Headers({"Content-type": ["application/x-www-form-urlencoded"],
                       "User-agent": ["reCAPTCHA Python"]})
    d = agent.request('POST', API_SSL_VERIFY_URL, headers, body)
    d.addCallbacks(_cbRequest, _ebRequest)
    return d
