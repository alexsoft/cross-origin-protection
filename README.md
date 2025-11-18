# Cross Origin Protection [![Latest Version on Packagist](https://img.shields.io/packagist/v/alexsoft/cross-origin-protection.svg?style=flat)](https://packagist.org/packages/alexsoft/cross-origin-protection) [![codecov](https://codecov.io/github/alexsoft/cross-origin-protection/graph/badge.svg?token=GDLJ85NE1Q)](https://codecov.io/github/alexsoft/cross-origin-protection)

This library is a port of [CrossOriginProtection component][cross-origin-protection-component] from Go.

You can read an introduction to the mentioned Go component here: [alexedwards.net/blog/preventing-csrf-in-go][alexedwards-intro].

## Overview

This is a small PSR-15/PSR-7-compatible middleware library for PHP which validates fetch metadata (Sec-Fetch-Site) and Origin headers. It follows the approach popularised by the Go CrossOriginProtection component.

This middleware is focused on rejecting unsafe cross-origin requests (a practical defense against certain CSRF/forged-request scenarios).

### Why use this

Protect state-changing endpoints from cross-site requests when browser fetch metadata is available.

Lightweight, framework-agnostic middleware for PSR-compatible stacks.

## Installation

Install with Composer:
```bash
composer require alexsoft/cross-origin-protection:^1.0
```

## Usage

```php
use Alexsoft\CrossOriginProtection\CrossOriginProtection;
use GuzzleHttp\Psr7\Request;

$result = (new CrossOriginProtection())->check(Request::fromGlobals()); // accepts instance of ServerRequestInterface

if ($result === null) {
    // request is considered safe
} else {
    // request is NOT considered safe
}
```

If `$result` is not `null`, it will be an instance of `CrossOriginRequestError` which has public property `$message` which can be used for logging. Usually it is discouraged to show this message to the user, it is preferable to show some more generic server error message.

## PSR-15 middleware usage

Get instance of `Psr\Http\Server\MiddlewareInterface` by calling `getMiddleware()` method. Then you can plug it into your stack.

```php
use Alexsoft\CrossOriginProtection\CrossOriginProtection;

$psr15Middleware = (new CrossOriginProtection())->getMiddleware();
```

## Configuration

`CrossOriginProtection` has 2 method that provide extension:
- `addInsecureBypassPattern(string $regex): void` – can be used to add **case-insensitive** regex for the URLs that need to be bypassed. All added regexes are combined with `|`, wrapped with leading and trailing slashes and have `i` (ignore case) flag added.
- `addTrustedOrigin(string|UriInterface $uri): void` – can be used to add trusted origins for which requests should be bypassed.

```php
use Alexsoft\CrossOriginProtection\CrossOriginProtection;
use GuzzleHttp\Psr7\Request;

$crossOriginProtection = new CrossOriginProtection();

$crossOriginProtection->addInsecureBypassPattern('\/internal\/'); // will bypass URLS with '/internal/' section in it

$crossOriginProtection->addTrustedOrigin('https://example.com');

// can be used directly
$crossOriginProtection->check(Request::fromGlobals()); // accepts instance of ServerRequestInterface

// or as PSR-15 middleware
$middleware = $crossOriginProtection->getMiddleware();
```

## Important notes

Because the middleware relies on browser-provided `Sec-Fetch-Site` and `Origin` headers, consider following:

### Safe methods
You typically only need to apply strict checks to state-changing methods (e.g. `POST`, `PUT`, `DELETE`, `PATCH`). `GET`, `HEAD` are usually safe but evaluate per-API.

### Fetch metadata support
`Sec-Fetch-Site` is not present in all browsers/clients. Falling back on comparing Origin and Host when `Sec-Fetch-Site` is missing can be risky: `Host` lacks scheme and that fallback has edge cases (e.g. http://example.com vs https://example.com). This should be mitigated with HTTP Strict Transport Security (HSTS). See the article for nuances.

### Not a complete protection
This middleware helps reject unsafe cross-origin requests but is not a complete CSRF protection on its own. Use it alongside other controls (CSRF tokens for browser forms, SameSite cookies, strong authentication).

When `Sec-Fetch-Site` is absent, implementation falls back to `Origin` vs `Host` checks; this fallback may introduce false-positives/negatives in mixed-scheme deployments (HTTP ↔ HTTPS). Test carefully.

Do not depend on header values from non-browser clients — spoilable by attackers. The middleware is primarily to harden browser-based attack surfaces.

[cross-origin-protection-component]: https://pkg.go.dev/net/http#CrossOriginProtection
[alexedwards-intro]: https://www.alexedwards.net/blog/preventing-csrf-in-go
