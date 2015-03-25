#!/usr/bin/env python
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

from __future__ import print_function

import os
import setuptools

from glob import glob

# Setup automatic versioning (see top-level versioneer.py file):
import versioneer
versioneer.VCS = "git"
versioneer.versionfile_source = 'txrecaptcha/_version.py'
versioneer.versionfile_build = 'txrecaptcha/_version.py'
versioneer.tag_prefix = 'txrecaptcha-'
versioneer.parentdir_prefix = 'txrecaptcha-'


PKG_PATH = 'txrecaptcha'
# The directory containing template files and other resources to serve on the
# web server:
SOURCE_TEMPLATES = os.path.join(PKG_PATH, 'templates')

# Directory to install docs, license, and other text resources into:
INSTALL_DOCS = os.path.join('share', 'doc', 'txrecaptcha')
# Directory to install HTML templates and other webserver resources into:
INSTALL_TEMPLATES = os.path.join('share', 'txrecaptcha')


def get_cmdclass():
    """Get our cmdclass dictionary for use in setuptool.setup().

    This must be done outside the call to setuptools.setup() because we need
    to add our own classes to the cmdclass dictionary, and then update that
    dictionary with the one returned from versioneer.get_cmdclass().
    """
    cmdclass = {}
    cmdclass.update(versioneer.get_cmdclass())
    return cmdclass

def get_requirements():
    """Extract the list of requirements from our requirements.txt.

    :rtype: 2-tuple
    :returns: Two lists, the first is a list of requirements in the form of
        pkgname==version. The second is a list of URIs or VCS checkout strings
        which specify the dependency links for obtaining a copy of the
        requirement.
    """
    requirements_file = os.path.join(os.getcwd(), 'requirements.txt')
    requirements = []
    links=[]
    try:
        with open(requirements_file) as reqfile:
            for line in reqfile.readlines():
                line = line.strip()
                if line.startswith('#'):
                    continue
                elif line.startswith(
                        ('https://', 'git://', 'hg://', 'svn://')):
                    links.append(line)
                else:
                    requirements.append(line)

    except (IOError, OSError) as error:
        print(error)

    return requirements, links

def get_template_files():
    """Return the paths to any web resource files to include in the package.

    :rtype: list
    :returns: Any files in :attr:`SOURCE_TEMPLATES` which match one of the glob
        patterns in :ivar:`include_patterns`.
    """
    include_patterns = ['*.html',
                        '*.txt',
                        '*.asc',
                        'assets/*.png',
                        'assets/*.svg',
                        'assets/css/*.css',
                        'assets/font/*.woff',
                        'assets/font/*.ttf',
                        'assets/font/*.svg',
                        'assets/font/*.eot']
    template_files = []

    for include_pattern in include_patterns:
        pattern = os.path.join(SOURCE_TEMPLATES, include_pattern)
        matches = glob(pattern)
        template_files.extend(matches)

    return template_files

def get_data_files(filesonly=False):
    """Return any hard-coded data_files which should be distributed.

    This is necessary so that both the distutils-derived :class:`installData`
    class and the setuptools ``data_files`` parameter include the same files.
    Call this function with ``filesonly=True`` to get a list of files suitable
    for giving to the ``package_data`` parameter in ``setuptools.setup()``.
    Or, call it with ``filesonly=False`` (the default) to get a list which is
    suitable for using as ``distutils.command.install_data.data_files``.

    :param bool filesonly: If true, only return the locations of the files to
        install, not the directories to install them into.
    :rtype: list
    :returns: If ``filesonly``, returns a list of file paths. Otherwise,
        returns a list of 2-tuples containing: one, the directory to install
        to, and two, the files to install to that directory.
    """
    data_files = []
    doc_files = ['README', 'LICENSE', 'requirements.txt']
    template_files = get_template_files()

    if filesonly:
        data_files.extend(doc_files)
        for lst in template_files:
            for filename in lst:
                if filename.startswith(PKG_PATH):
                    # The +1 gets rid of the '/' at the beginning:
                    filename = filename[len(PKG_PATH) + 1:]
                    data_files.append(filename)
    else:
        data_files.append((INSTALL_DOCS, doc_files))
        data_files.append((INSTALL_TEMPLATES, template_files))

    return data_files


# If there is an environment variable TXRECAPTCHA_INSTALL_DEPENDENCIES=0, it will
# disable checking for, fetching, and installing txrecaptcha's dependencies with
# easy_install.
#
# Setting TXRECAPTCHA_INSTALL_DEPENDENCIES=0 is *highly* recommended, because
# easy_install is a security nightmare.  Automatically installing dependencies
# is enabled by default, however, because this is how all Python packages are
# supposed to work.
if bool(int(os.environ.get("TXRECAPTCHA_INSTALL_DEPENDENCIES", 1))):
    requires, deplinks = get_requirements()
else:
    requires, deplinks = [], []


setuptools.setup(
    name='txrecaptcha',
    version=versioneer.get_version(),
    description='Twisted reCAPTCHA client',
    author='Isis Lovecruft',
    author_email='isis at torproject dot org',
    maintainer='Isis Agora Lovecruft',
    maintainer_email='isis at torproject dot org 0xA3ADB67A2CDB8B35',
    url='https://www.torproject.org',
    download_url='https://github.com/isislovecruft/txrecaptcha.git',
    packages=['txrecaptcha'],
    extras_require={'test': ["coverage==3.7.1"],
                    'templates': ["Mako>=0.8.1"]},
    zip_safe=False,
    cmdclass=get_cmdclass(),
    include_package_data=True,
    install_requires=requires,
    dependency_links=deplinks,
    package_data={'txrecaptcha': get_data_files(filesonly=True)},
    keywords="captcha, recaptcha, google, zope, twisted, template, mako",
    platforms="Linux, BSD, OSX, Windows",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Framework :: Twisted",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: Android",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: BSD",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content :: CGI Tools/Libraries",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
        "Topic :: Internet :: WWW/HTTP :: Site Management",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Software Development :: User Interfaces",]
)
