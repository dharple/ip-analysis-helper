# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository.

## Project Overview

This is a CLI data-conversion utility that transforms IANA IPv4/IPv6 special
address registry CSV files into PHP array files consumed by the [ip-analysis]
library's `SpecialAddressBlock\Factory` class.

## Commands

### Setup

```bash
composer install
```

### Running

```bash
# Full conversion pipeline (downloads CSVs must already be in data/)
bin/convert

# Run a single conversion manually
bin/console iana:convert data/iana-ipv4-special-registry-1.csv --multicast=ipv4 --force
bin/console iana:convert data/iana-ipv6-special-registry-1.csv --multicast=ipv6 --force
```

### Dev Tools

```bash
# All of these commands can take one or more filenames or directories on the
# command line, to narrow the scope of their execution

composer phpstan   # Static Analysis
composer phpcs     # Check Code Style
composer phpcbf    # Fix Code Style
composer rector     # Show Opportunities for Automatic Refactoring

# Direct access tools

vendor/bin/rector   # Do Automatic Refactoring
```

## Architecture

Symfony MicroKernel console application — no HTTP routing, no web layer.

**Data pipeline**: IANA CSV → Symfony Serializer deserializes rows into `SpecialAddressBlock` objects (from `outsanity/ip-analysis`) → `IanaConvertCommand` builds a PHP array → `var_export()` output is regex-cleaned into clean array syntax → written to `data/`.

**`src/Command/IanaConvertCommand.php`** is the entire business logic:
- Uses `GetSetMethodNormalizer` + `CsvEncoder` for CSV deserialization
- `@SerializedName` annotations map CSV column headers to object properties
- CIDR blocks covering multiple addresses are expanded/split
- `--multicast` flag adds multicast address blocks for IPv4 or IPv6
- `--force` flag overwrites existing output files

## Code Style

The custom `outsanity/phpcs` ruleset (`vendor/outsanity/phpcs/Outsanity/ruleset.xml`) is the enforced standard. Run `composer phpcbf` after edits. Rector is configured for PHP 8.3 and Symfony 6.4 patterns (`rector.php`).

[ip-analysis]: https://github.com/dharple/ip-analysis
