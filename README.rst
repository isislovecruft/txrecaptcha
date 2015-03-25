*************************************************************
txrecaptcha |Latest Version| |Build Status| |Coverage Status|
*************************************************************

txrecaptcha is a Twisted-based reCAPTCHA client.

Unlike the official Google Python recaptcha-client_, which is hardcoded_ to use
plaintext HTTP, txrecaptcha *always* uses TLS with strict hostname checking
(for Twisted<=13.2.0) or certificate pinning (for Twisted>=14.0.0).

Small portions of this code were taken from the official Google Python
recaptcha-client_ module, version 1.0.6.  Those portions are
:class:`RecaptchaResponse`, :data:`API_SERVER`, They total 5 lines of code,
which are copyright the authors of the recaptcha-client_ package.

.. |Latest Version| image:: https://pypip.in/version/txrecaptcha/badge.svg?style=flat
   :target: https://pypi.python.org/pypi/txrecaptcha/
.. |Build Status| image:: https://travis-ci.org/isislovecruft/txrecaptcha.svg
   :target: https://travis-ci.org/isislovecruft/txrecaptcha
.. |Coverage Status| image:: https://coveralls.io/repos/isislovecruft/txrecaptcha/badge.png?branch=develop
   :target: https://coveralls.io/r/isislovecruft/txrecaptcha?branch=develop

.. _hardcoded: https://code.google.com/p/recaptcha/source/browse/trunk/recaptcha-plugins/python/recaptcha/client/captcha.py#76
.. _recaptcha-client: https://pypi.python.org/pypi/recaptcha-client/1.0.6

.. contents::
   :backlinks: entry
