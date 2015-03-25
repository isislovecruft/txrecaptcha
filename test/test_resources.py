# -*- coding: utf-8 -*-
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

"""Unittests for the txrecaptcha.resources module."""

from __future__ import print_function

import logging
import ipaddr

from BeautifulSoup import BeautifulSoup

from twisted.internet import reactor
from twisted.internet import task
from twisted.trial import unittest
from twisted.web.resource import Resource

from txrecaptcha import resources


# For additional logger output for debugging, comment out the following:
logging.disable(50)
# and then uncomment the following line:
#resources.logging.getLogger().setLevel(10)


class ReCaptchaProtectedResourceTests(unittest.TestCase):
    """Tests for :mod:`bridgedb.HTTPServer.ReCaptchaProtectedResource`."""

    def setUp(self):
        """Create a :class:`HTTPServer.WebResourceBridges` and protect it with
        a :class:`ReCaptchaProtectedResource`.
        """
        self.timeout = 10.0  # Can't take longer than that, right?
        # Set up our resources to fake a minimal HTTP(S) server:
        self.pagename = b'captcha.html'
        self.root = Resource()
        # (None, None) is the (distributor, scheduleInterval):
        self.protectedResource = HTTPServer.WebResourceBridges(None, None)
        self.captchaResource = HTTPServer.ReCaptchaProtectedResource(
            publicKey='23',
            secretKey='42',
            remoteIP='111.111.111.111',
            useForwardedHeader=True,
            protectedResource=self.protectedResource)

        self.root.putChild(self.pagename, self.captchaResource)

        # Set up the basic parts of our faked request:
        self.request = DummyRequest([self.pagename])

    def tearDown(self):
        """Cleanup method for removing timed out connections on the reactor.

        This seems to be the solution for the dirty reactor due to
        ``DelayedCall``s which is mentioned at the beginning of this
        file. There doesn't seem to be any documentation anywhere which
        proposes this solution, although this seems to solve the problem.
        """
        for delay in reactor.getDelayedCalls():
            try:
                delay.cancel()
            except (AlreadyCalled, AlreadyCancelled):
                pass

    def test_renderDeferred_invalid(self):
        """:meth:`_renderDeferred` should redirect a ``Request`` (after the
        CAPTCHA was NOT xsuccessfully solved) which results from a
        ``Deferred``'s callback.
        """
        self.request.method = b'POST'

        def testCB(request):
            """Check the ``Request`` returned from ``_renderDeferred``."""
            self.assertIsInstance(request, DummyRequest)
            soup = BeautifulSoup(b''.join(request.written)).find('meta')['http-equiv']
            self.assertEqual(soup, 'refresh')

        d = task.deferLater(reactor, 0, lambda x: x, (False, self.request))
        d.addCallback(self.captchaResource._renderDeferred)
        d.addCallback(testCB)
        return d

    def test_renderDeferred_valid(self):
        """:meth:`_renderDeferred` should correctly render a ``Request`` (after
        the CAPTCHA has been successfully solved) which results from a
        ``Deferred``'s callback.
        """
        self.request.method = b'POST'

        def testCB(request):
            """Check the ``Request`` returned from ``_renderDeferred``."""
            self.assertIsInstance(request, DummyRequest)
            html = b''.join(request.written)
            self.assertSubstring('Uh oh, spaghettios!', html)

        d = task.deferLater(reactor, 0, lambda x: x, (True, self.request))
        d.addCallback(self.captchaResource._renderDeferred)
        d.addCallback(testCB)
        return d

    def test_renderDeferred_nontuple(self):
        """:meth:`_renderDeferred` should correctly render a ``Request`` (after
        the CAPTCHA has been successfully solved) which results from a
        ``Deferred``'s callback.
        """
        self.request.method = b'POST'

        def testCB(request):
            """Check the ``Request`` returned from ``_renderDeferred``."""
            self.assertIs(request, None)

        d = task.deferLater(reactor, 0, lambda x: x, (self.request))
        d.addCallback(self.captchaResource._renderDeferred)
        d.addCallback(testCB)
        return d

    def test_checkSolution_blankFields(self):
        """:meth:`HTTPServer.ReCaptchaProtectedResource.checkSolution` should
        return a redirect if is the solution field is blank.
        """
        self.request.method = b'POST'
        self.request.addArg('captcha_challenge_field', '')
        self.request.addArg('captcha_response_field', '')

        self.assertEqual((False, self.request),
                         self.successResultOf(
                             self.captchaResource.checkSolution(self.request)))

    def test_getRemoteIP_useRandomIP(self):
        """Check that removing our remoteip setting produces a random IP."""
        self.captchaResource.remoteIP = None
        ip = self.captchaResource.getRemoteIP()
        realishIP = ipaddr.IPv4Address(ip).compressed
        self.assertTrue(realishIP)
        self.assertNotEquals(realishIP, '111.111.111.111')

    def test_getRemoteIP_useConfiguredIP(self):
        """Check that our remoteip setting is used if configured."""
        ip = self.captchaResource.getRemoteIP()
        realishIP = ipaddr.IPv4Address(ip).compressed
        self.assertTrue(realishIP)
        self.assertEquals(realishIP, '111.111.111.111')

    def test_render_GET_missingTemplate(self):
        """render_GET() with a missing template should raise an error and
        return the result of replaceErrorPage().
        """
        oldLookup = HTTPServer.lookup
        try:
            HTTPServer.lookup = None
            self.request.method = b'GET'
            page = self.captchaResource.render_GET(self.request)
            errorPage = HTTPServer.replaceErrorPage(Exception('kablam'))
            self.assertEqual(page, errorPage)
        finally:
            HTTPServer.lookup = oldLookup

    def test_render_POST_blankFields(self):
        """render_POST() with a blank 'captcha_response_field' should return
        a redirect to the CaptchaProtectedResource page.
        """
        self.request.method = b'POST'
        self.request.addArg('captcha_challenge_field', '')
        self.request.addArg('captcha_response_field', '')

        page = self.captchaResource.render_POST(self.request)
        self.assertEqual(page, HTTPServer.server.NOT_DONE_YET)

    def test_render_POST_wrongSolution(self):
        """render_POST() with a wrong 'captcha_response_field' should return
        a redirect to the CaptchaProtectedResource page.
        """
        expectedChallenge = '23232323232323232323'
        expectedResponse = 'awefawefaefawefaewf'

        self.request.method = b'POST'
        self.request.addArg('captcha_challenge_field', expectedChallenge)
        self.request.addArg('captcha_response_field', expectedResponse)

        page = self.captchaResource.render_POST(self.request)
        self.assertEqual(page, HTTPServer.server.NOT_DONE_YET)
