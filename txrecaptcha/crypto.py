# -*- coding: utf-8 ; test-case-name: test_crypto -*-
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

"""txrecaptcha general cryptographic utilities."""

import logging
import re
import urllib

import OpenSSL

from twisted.internet import ssl


class SSLVerifyingContextFactory(ssl.CertificateOptions):
    """``OpenSSL.SSL.Context`` factory which does full certificate-chain and
    hostname verfication.
    """
    isClient = True

    def __init__(self, url, **kwargs):
        """Create a client-side verifying SSL Context factory.

        To pass acceptable certificates for a server which does
        client-authentication checks: initialise with a ``caCerts=[]`` keyword
        argument, which should be a list of ``OpenSSL.crypto.X509`` instances
        (one for each peer certificate to add to the store), and set
        ``SSLVerifyingContextFactory.isClient=False``.

        :param str url: The URL being requested by an
            :api:`twisted.web.client.Agent`.
        :param bool isClient: True if we're being used in a client
            implementation; False if we're a server.
        """
        self.hostname = self.getHostnameFromURL(url)

        # ``verify`` here refers to server-side verification of certificates
        # presented by a client:
        self.verify = False if self.isClient else True
        super(SSLVerifyingContextFactory, self).__init__(verify=self.verify,
                                                         fixBrokenPeers=True,
                                                         **kwargs)

    def getContext(self, hostname=None, port=None):
        """Retrieve a configured ``OpenSSL.SSL.Context``.

        Any certificates in the ``caCerts`` list given during initialisation
        are added to the ``Context``'s certificate store.

        The **hostname** and **port** arguments seem unused, but they are
        required due to some Twisted and pyOpenSSL internals. See
        :api:`twisted.web.client.Agent._wrapContextFactory`.

        :rtype: ``OpenSSL.SSL.Context``
        :returns: An SSL Context which verifies certificates.
        """
        ctx = super(SSLVerifyingContextFactory, self).getContext()
        store = ctx.get_cert_store()
        verifyOptions = OpenSSL.SSL.VERIFY_PEER
        ctx.set_verify(verifyOptions, self.verifyHostname)
        return ctx

    def getHostnameFromURL(self, url):
        """Parse the hostname from the originally requested URL.

        :param str url: The URL being requested by an
            :api:`twisted.web.client.Agent`.
        :rtype: str
        :returns: The full hostname (including any subdomains).
        """
        hostname = urllib.splithost(urllib.splittype(url)[1])[0]
        logging.debug("Parsed hostname %r for cert CN matching." % hostname)
        return hostname

    def verifyHostname(self, connection, x509, errnum, depth, okay):
        """Callback method for additional SSL certificate validation.

        If the certificate is signed by a valid CA, and the chain is valid,
        verify that the level 0 certificate has a subject common name which is
        valid for the hostname of the originally requested URL.

        :param connection: An ``OpenSSL.SSL.Connection``.
        :param x509: An ``OpenSSL.crypto.X509`` object.
        :param errnum: A pyOpenSSL error number. See that project's docs.
        :param depth: The depth which the current certificate is at in the
            certificate chain.
        :param bool okay: True if all the pyOpenSSL default checks on the
            certificate passed. False otherwise.
        """
        commonName = x509.get_subject().commonName
        logging.debug("Received cert at level %d: '%s'" % (depth, commonName))

        # We only want to verify that the hostname matches for the level 0
        # certificate:
        if okay and (depth == 0):
            cn = commonName.replace('*', '.*')
            hostnamesMatch = re.search(cn, self.hostname)
            if not hostnamesMatch:
                logging.warn("Invalid certificate subject CN for '%s': '%s'"
                             % (self.hostname, commonName))
                return False
            logging.debug("Valid certificate subject CN for '%s': '%s'"
                          % (self.hostname, commonName))
        return True
