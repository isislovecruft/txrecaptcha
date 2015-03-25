# -*- coding: utf-8 ; test-case-name: test_captcha -*-
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

import logging
import urllib2

from BeautifulSoup import BeautifulSoup

from zope.interface import (
    Interface,
    Attribute,
    implements
)

from txrecaptcha.recaptcha import API_SSL_SERVER


class CaptchaKeyError(Exception):
    """Raised if a CAPTCHA system's keys are invalid or missing."""


class ICaptcha(Interface):
    """Interface specification for CAPTCHAs."""

    image = Attribute(
        "A string containing the contents of a CAPTCHA image file.")
    challenge = Attribute(
        "A unique string associated with the dispursal of this CAPTCHA.")
    publicKey = Attribute(
        "A public key used for encrypting CAPTCHA challenge strings.")
    secretKey = Attribute(
        "A private key used for decrypting challenge strings during CAPTCHA "
        "solution verification.")

    def get():
        """Retrieve a new CAPTCHA image."""


class Captcha(object):
    """A generic CAPTCHA base class.

    :ivar str image: The CAPTCHA image.
    :ivar str challenge: A challenge string which should permit checking of
        the client's CAPTCHA solution in some manner. In stateless protocols
        such as HTTP, this should be passed along to the client with the
        CAPTCHA image.
    :ivar publicKey: A public key used for encrypting CAPTCHA challenge strings.
    :ivar secretKey: A private key used for decrypting challenge strings during
        CAPTCHA solution verification.
    """
    implements(ICaptcha)

    def __init__(self, publicKey=None, secretKey=None):
        """Obtain a new CAPTCHA for a client."""
        self.image = None
        self.challenge = None
        self.publicKey = publicKey
        self.secretKey = secretKey

    def get(self):
        """Retrieve a new CAPTCHA image and its associated challenge string.

        The image and challenge will be stored as :ivar:`image` and
        :ivar:`challenge, respectively.
        """
        self.image = None
        self.challenge = None


class ReCaptcha(Captcha):
    """A CAPTCHA obtained from a remote reCaptcha_ API server.

    :ivar str image: The CAPTCHA image.
    :ivar str challenge: The ``'recaptcha_challenge_response'`` HTTP form
        field to pass to the client, along with the CAPTCHA image. See
        :doc:`BridgeDB's captcha.html <templates/captcha.html>` Mako_ template
        for an example usage.
    :ivar str publicKey: The public reCaptcha API key.
    :ivar str secretKey: The private reCaptcha API key.

    .. _reCaptcha: https://code.google.com/p/recaptcha/
    .. _Mako: http://docs.makotemplates.org/en/latest/syntax.html#page
    """

    def __init__(self, publicKey=None, secretKey=None):
        """Create a new ReCaptcha CAPTCHA.

        :param str publicKey: The public reCaptcha API key.
        :param str secretKey: The private reCaptcha API key.
        """
        super(ReCaptcha, self).__init__(publicKey=publicKey,
                                        secretKey=secretKey)

    def get(self):
        """Retrieve a CAPTCHA from the reCaptcha API server.

        This simply requests a new CAPTCHA from
        ``recaptcha.client.captcha.API_SSL_SERVER`` and parses the returned
        HTML to extract the CAPTCHA image and challenge string. The image is
        stored at ``ReCaptcha.image`` and the challenge string at
        ``ReCaptcha.challenge``.

        :raises CaptchaKeyError: If either the :ivar:`publicKey` or
            :ivar:`secretKey` are missing.
        :raises HTTPError: If the server returned any HTTP error status code.
        """
        if not self.publicKey or not self.secretKey:
            raise CaptchaKeyError('You must supply recaptcha API keys')

        urlbase = API_SSL_SERVER
        form = "/noscript?k=%s" % self.publicKey

        # Extract and store image from recaptcha
        html = urllib2.urlopen(urlbase + form).read()
        # FIXME: The remaining lines currently cannot be reliably unit tested:
        soup = BeautifulSoup(html)                           # pragma: no cover
        imgurl = urlbase + "/" +  soup.find('img')['src']    # pragma: no cover
        cField = soup.find(                                  # pragma: no cover
            'input', {'name': 'recaptcha_challenge_field'})  # pragma: no cover
        self.challenge = str(cField['value'])                # pragma: no cover
        self.image = urllib2.urlopen(imgurl).read()          # pragma: no cover
