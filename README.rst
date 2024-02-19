ImageCloak
==========

*ImageCloak* is a simple framework for managing encrypted server
images.

It uses libsodium's ``secretstream`` (XChaCha20-Poly1305) for
encrypting files and ``crypto_box`` (X25519-XSalsa20-Poly1305) for
wrapping stream keys.  Those wrap keys are stored on each server in an
EFI variable (to make them persistent across disk wipes).


Building ImageCloak
-------------------

You need:

- a C17 compiler
- `libsodium <https://www.libsodium.org/>`__
- `Meson 0.56 <http://mesonbuild.com/>`__ and `Ninja
  <https://ninja-build.org/>`__

Get the source code::

 git clone --recursive https://github.com/CM4all/ImageCloak

Run ``meson``::

 meson setup output

Compile and install::

 ninja -C output
 ninja -C output install


Building the Debian package
---------------------------

After installing the build dependencies, run::

 dpkg-buildpackage -rfakeroot -b -uc -us


Using ImageCloak
----------------

First generate a keypair on all servers::

  # cm4all-image-cloak efi-keypair
  08ff92a3bcc2df4720076cb33f3a68a20533d1cd88e7c51f0e5db01878ecdc05

This stores both keys in EFI variables and prints the public key.

Encrypt a server image with a new stream key::

  # cm4all-image-cloak encrypt-stream foo_amd64.img.key <foo_amd64.img >foo_amd64.img.crypt

The stream key is written to the file ``foo_amd64.img.key`` and the
encrypted image is written to ``foo_amd64.img.crypt``.  To allow
servers to decrypt it, create a seal for each server::

  # mkdir seal
  # cm4all-image-cloak multi-seal foo_amd64.img.key seal \
      08ff92a3bcc2df4720076cb33f3a68a20533d1cd88e7c51f0e5db01878ecdc05 \
      d00174b35959ff2465acfe7a615b17fd28a4c7c11fd9a61068528a3d4b2cd32b
  # tar cvfC foo_amd64.img.seal seal .
  ./
  ./d00174b35959ff2465acfe7a615b17fd28a4c7c11fd9a61068528a3d4b2cd32b
  ./08ff92a3bcc2df4720076cb33f3a68a20533d1cd88e7c51f0e5db01878ecdc05

(This example creates seals for two servers.  You can specify any
number of server public keys on the command line.)

Copy both files (``foo_amd64.img.crypt`` and ``foo_amd64.img.seal``)
to where all servers can download them.

On each server, download and unpack the seal tarball; after that, you
can decrypt the image::

  mkdir seal
  wget -q http://192.168.0.1/foo_amd64.img.seal -O - |tar xvC seal
  ./
  ./d00174b35959ff2465acfe7a615b17fd28a4c7c11fd9a61068528a3d4b2cd32b
  ./08ff92a3bcc2df4720076cb33f3a68a20533d1cd88e7c51f0e5db01878ecdc05
  wget -q http://192.168.0.1/foo_amd64.img.crypt -O - | \
    cm4all-image-cloak efi-decrypt-stream seal |tar xC /target

The ``efi-decrypt-stream`` command loads the keypair from EFI
variables and looks for a seal file in the specified directory; if one
is found, it decrypts the stream given on stdin and writes decrypted
data to stdout.  In this example, the file is streamed from a web
server with ``wget``, decrypted and extracted with ``tar``.
