# PHP IP Analyzer Helper

Generates data files for the [IP Analysis] library.

This is probably *not* the package you're looking for.

## Steps

1. Download the rules from the [IANA IPv4 Special Address Registry]
   and the [IANA IPv6 Special Address Registry] into the `data/` directory.
2. Run `bin/convert`.
3. Copy the data out of the resultant `data/*.php` files and put it in to the
   `$allRaw` property of `Outsanity\IpAnalysis\SpecialAddressBlock\Factory`.

[IANA IPv4 Special Address Registry]: https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
[IANA IPv6 Special Address Registry]: https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml

[IP Analysis]: https://github.com/dharple/ip-analysis
