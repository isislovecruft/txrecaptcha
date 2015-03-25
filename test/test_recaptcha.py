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

"""Unittests for the txrecaptcha.recaptcha module."""

import logging

from twisted.internet import defer
from twisted.internet import reactor
from twisted.internet.base import DelayedCall
from twisted.internet.error import ConnectionDone
from twisted.internet.error import ConnectionLost
from twisted.internet.error import ConnectionRefusedError
from twisted.test import proto_helpers
from twisted.trial import unittest
from twisted.python import failure
from twisted.web.client import ResponseDone
from twisted.web.http_headers import Headers
from twisted.web.iweb import IBodyProducer

from zope.interface.verify import verifyObject

from txrecaptcha import recaptcha


logging.disable(50)

# Set ``DelayedCall.debug=True``, because the following traceback was occuring:
#
# Traceback (most recent call last):
# Failure: twisted.trial.util.DirtyReactorAggregateError: Reactor was unclean.
# DelayedCalls: (set twisted.internet.base.DelayedCall.debug = True to debug)
# <DelayedCall 0x1ba5b90 [29.991571188s] called=0 cancelled=0
#     Client.failIfNotConnected(TimeoutError('',))>
# <DelayedCall 0x1baa3f8 [59.9993360043s] called=0 cancelled=0
#     ThreadedResolver._cleanup('www.google.com', <Deferred at 0x1baa320>)>
DelayedCall.debug = True


class MockResponse(object):
    """Fake :api:`twisted.internet.interfaces.IResponse` for testing readBody
    that just captures the protocol passed to deliverBody.

    :ivar protocol: After :meth:`deliverBody` is called, the protocol it was
        called with.
    """
    code = 200
    phrase = "OK"

    def __init__(self, headers=None):
        """Create a mock response.

        :type headers: :api:`twisted.web.http_headers.Headers`
        :param headers: The headers for this response.  If ``None``, an empty
            ``Headers`` instance will be used.
        """
        if headers is None:
            headers = Headers()
        self.headers = headers

    def deliverBody(self, protocol):
        """Just record the given protocol without actually delivering anything
        to it.
        """
        self.protocol = protocol


class RecaptchaResponseProtocolTests(unittest.TestCase):
    """Tests for txrecaptcha.recaptcha.RecaptchaResponseProtocol."""

    def setUp(self):
        """Setup the tests."""
        self.finished = defer.Deferred()
        self.proto = recaptcha.RecaptchaResponseProtocol(self.finished)

    def _test(self, responseBody, connCloseError):
        """Deliver the **responseBody** to
        ``RecaptchaResponseProtocol.dataReceived``, and then lose the transport
        connection with a **connCloseError**.

        The resulting ``RecaptchaResponseProtocol.response`` should be equal
        to the original **responseBody**.
        """
        self.proto.dataReceived(responseBody)
        self.proto.connectionLost(failure.Failure(connCloseError()))
        self.assertEqual(responseBody, self.proto.response)
        response = self.successResultOf(self.finished)
        return response

    def test_trueResponse(self):
        """A valid API response which states 'true' should result in
        ``RecaptchaResponse.is_valid`` being ``True`` after receiving a
        ``ConnectionDone``.
        """
        responseBody = "true\nsome-reason-or-another\n"
        response = self._test(responseBody, ConnectionDone)
        self.assertIsInstance(response, recaptcha.RecaptchaResponse)
        self.assertTrue(response.is_valid)
        self.assertEqual(response.error_code, "some-reason-or-another")

    def test_falseResponse(self):
        """A valid API response which states 'false' should result in
        ``RecaptchaResponse.is_valid`` being ``false``.
        """
        responseBody = "false\nsome-reason-or-another\n"
        response = self._test(responseBody, ResponseDone)
        self.assertIsInstance(response, recaptcha.RecaptchaResponse)
        self.assertIs(response.is_valid, False)
        self.assertEqual(response.error_code, "some-reason-or-another")

    def test_responseDone(self):
        """A valid response body with a ``ResponseDone`` should result in
        ``RecaptchaResponse.is_valid`` which is ``True``.
        """
        responseBody = "true\nsome-reason-or-another\n"
        response = self._test(responseBody, ResponseDone)
        self.assertIsInstance(response, recaptcha.RecaptchaResponse)
        self.assertTrue(response.is_valid)
        self.assertEqual(response.error_code, "some-reason-or-another")

    def test_incompleteResponse(self):
        """ConnectionLost with an incomplete response should produce a specific
        RecaptchaResponse.error_code message.
        """
        responseBody = "true"
        response = self._test(responseBody, ConnectionLost)
        self.assertIs(response.is_valid, False)
        self.assertEqual(response.error_code,
                         "Couldn't parse response from reCaptcha API server")


class BodyProducerTests(unittest.TestCase):
    """Test for :class:`txrecaptcha.recaptcha.BodyProducer`."""

    def setUp(self):
        """Setup the tests."""
        self.content = 'Line 1\r\nLine 2\r\n'
        self.producer = recaptcha._BodyProducer(self.content)

    def test_interface(self):
        """BodyProducer should correctly implement IBodyProducer interface."""
        self.assertTrue(verifyObject(IBodyProducer, self.producer))

    def test_length(self):
        """BodyProducer.length should be equal to the total contect length."""
        self.assertEqual(self.producer.length, len(self.content))

    def test_body(self):
        """BodyProducer.body should be the content."""
        self.assertEqual(self.producer.body, self.content)

    def test_startProducing(self):
        """:func:`recaptcha.BodyProducer.startProducing` should deliver the
        original content to an IConsumer implementation.
        """
        consumer = proto_helpers.StringTransport()
        consumer.registerProducer(self.producer, False)
        self.producer.startProducing(consumer)
        self.assertEqual(consumer.value(), self.content)
        consumer.clear()


class SubmitTests(unittest.TestCase):
    """Tests for :func:`txrecaptcha.recaptcha.submit`."""

    def setUp(self):
        """Setup the tests."""
        self.challenge = (
            "03AHJ_Vutbkv3jolF5JXfJTFf5wtbdkwIJF7WA77WYjLfOUEvKW7eHBiEDKQB__7"
            "GHtUOmXC13GFYIt09HuS-ZN1j5EuDmC7bzHpHUAlpI5rbOvByypYt1vtskwnN24g"
            "zwWkrtKj8yGBWRNFljFMvtqYqHeHwJitRktSfKmV4q9VVgLBwkwlbvGUICmGaDrx"
            "dg5lYV3hpijIkmnwXygWIwoqQ0VeCgPQQ1Yw")
        self.response = "cknwnlym+ullyHLy"
        self.key = '6BdkT-18FFHAAA349auGabiqntjRJAiEM2cqPMaM8'
        self.ip = "1.2.3.4"

    def test_submit_emptyResponseField(self):
        """An empty 'recaptcha_response_field' should return a deferred which
        callbacks with a RecaptchaResponse whose error_code is
        'incorrect-captcha-sol'.
        """
        def checkResponse(response):
            """Check that the response is a
            :class:`txcaptcha.RecaptchaResponse`.
            """
            self.assertIsInstance(response, recaptcha.RecaptchaResponse)
            self.assertIs(response.is_valid, False)
            self.assertEqual(response.error_code, 'incorrect-captcha-sol')

        d = recaptcha.submit(self.challenge, '', self.key, self.ip)
        d.addCallback(checkResponse)
        return d

    def test_submit_returnsDeferred(self):
        """:func:`recaptcha.submit` should return a deferred."""
        response = recaptcha.submit(self.challenge, self.response, self.key, self.ip)
        self.assertIsInstance(response, defer.Deferred)

    def test_submit_resultIsRecaptchaResponse(self):
        """Regardless of success or failure, the deferred returned from
        :func:`recaptcha.submit` should be a :class:`recaptcha.RecaptchaResponse`.
        """
        def checkResponse(response):
            """Check that the response is a
            :class:`txcaptcha.RecaptchaResponse`.
            """
            self.assertIsInstance(response, recaptcha.RecaptchaResponse)
            self.assertIsInstance(response.is_valid, bool)
            self.assertIsInstance(response.error_code, basestring)

        d = recaptcha.submit(self.challenge, self.response, self.key, self.ip)
        d.addCallback(checkResponse)
        return d

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


class MiscTests(unittest.TestCase):
    """Tests for miscellaneous functions in :mod:`txrecaptcha.recaptcha`."""

    def test_cbRequest(self):
        """Send a :class:`MockResponse` and check that the resulting protocol
        is a :class:`txrecaptcha.recaptcha.RecaptchaResponseProtocol`.
        """
        response = MockResponse()
        result = recaptcha._cbRequest(response)
        self.assertIsInstance(result, defer.Deferred)
        self.assertIsInstance(response.protocol,
                              recaptcha.RecaptchaResponseProtocol)

    def test_ebRequest(self):
        """Send a :api:`twisted.python.failure.Failure` and check that the
        resulting protocol is a
        :class:`txrecaptcha.recaptcha.RecaptchaResponseProtocol`.
        """
        msg = "Einhorn"
        fail = failure.Failure(ConnectionRefusedError(msg))
        result = recaptcha._ebRequest(fail)
        self.assertIsInstance(result, recaptcha.RecaptchaResponse)
        self.assertRegexpMatches(result.error_code, msg)

    def test_encodeIfNecessary(self):
        """:func:`txrecapcha.recaptcha._encodeIfNecessary` should convert unicode
        objects into strings.
        """
        origString = unicode('abc')
        self.assertIsInstance(origString, unicode)
        newString = recaptcha._encodeIfNecessary(origString)
        self.assertIsInstance(newString, str)
