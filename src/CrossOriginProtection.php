<?php

declare(strict_types=1);

namespace Alexsoft\CrossOriginProtection;

use Alexsoft\CrossOriginProtection\Exception\InvalidArgumentException;
use Http\Discovery\Psr17Factory;
use InvalidArgumentException as BaseInvalidArgumentException;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriFactoryInterface;
use Psr\Http\Message\UriInterface;

final class CrossOriginProtection
{
    /** @var array<string, bool> */
    private array $trustedOrigins = [];

    /** @var list<non-empty-string> */
    private array $bypassPatterns = [];

    public function __construct(
        private readonly UriFactoryInterface $uriFactory = new Psr17Factory(),
    ) {}

    /**
     * @api
     */
    public function check(ServerRequestInterface $request): ?CrossOriginRequestError
    {
        if (in_array(strtoupper($request->getMethod()), ['GET', 'HEAD', 'OPTIONS'], true)) {
            return null;
        }

        $secFetchLine = $request->getHeaderLine('Sec-Fetch-Site');

        switch ($secFetchLine) {
            case '':
                // proceed with checking Origin header
                break;
            case 'same-origin':
            case 'none':
                // it is safe, proceed with request
                return null;
            default: // would handle same-site and cross-site cases
                if ($this->isExempt($request)) {
                    return null;
                }

                return CrossOriginRequestError::fromSecFetchSideHeader();
        }

        $origin = $request->getHeaderLine('Origin');

        if ($origin === '') {
            // Neither Sec-Fetch-Site nor Origin headers are present.
            // Either the request is same-origin or not a browser request.
            return null;
        }

        $originUri = $this->uriFactory->createUri($origin);

        if ($this->areHostAndPortSame($originUri, $request->getUri())) {
            // The Origin header matches the Host header. Note that the Host header
            // doesn't include the scheme, so we don't know if this might be an
            // HTTP->HTTPS cross-origin request. Sites should mitigate
            // this with HTTP Strict Transport Security (HSTS).
            return null;
        }

        if ($this->isExempt($request)) {
            return null;
        }

        return CrossOriginRequestError::fromOldBrowser();
    }

    /**
     * @api
     */
    public function addInsecureBypassPattern(string $regex): void
    {
        if ($regex === '') {
            throw new InvalidArgumentException('Regex must not be empty.');
        }

        $this->bypassPatterns[] = $regex;
    }

    /**
     * AddTrustedOrigin allows all requests with an [Origin] header
     * which exactly matches the given value.
     *
     * Origin header values are of the form 'scheme://host[:port]'.
     *
     * @throws InvalidArgumentException
     *
     * @api
     */
    public function addTrustedOrigin(string|UriInterface $uri): void
    {
        if (!($uri instanceof UriInterface)) {
            try {
                $uri = $this->uriFactory->createUri($uri);
            } catch (BaseInvalidArgumentException $exception) {
                throw new InvalidArgumentException("Invalid origin {$uri}: could not parse", previous: $exception);
            }
        }

        if ($uri->getScheme() === '') {
            $uri = trim((string)$uri, '/');

            throw new InvalidArgumentException("Invalid origin {$uri}: scheme is required");
        }

        if ($uri->getHost() === '') { // TODO recheck, this case is probably handled by catching MalformedUriException above
            throw new InvalidArgumentException("Invalid origin {$uri}: host is required");
        }

        if ($uri->getPath() !== '' || $uri->getQuery() !== '' || $uri->getFragment() !== '') {
            throw new InvalidArgumentException("Invalid origin {$uri}: path, query, and fragment are not allowed");
        }

        $this->trustedOrigins[$this->generateOriginString($uri)] = true;
    }

    private function generateOriginString(UriInterface $uri): string
    {
        $str = "{$uri->getScheme()}://{$uri->getHost()}";

        if ($uri->getPort() !== null) {
            $str .= ":{$uri->getPort()}";
        }

        return $str;
    }

    /**
     * @api
     */
    public function getMiddleware(): CrossOriginProtectionMiddleware
    {
        return new CrossOriginProtectionMiddleware($this);
    }

    private function areHostAndPortSame(UriInterface $uri, UriInterface $otherUri): bool
    {
        return $this->getHostWithPort($uri) === $this->getHostWithPort($otherUri);
    }

    private function getHostWithPort(UriInterface $uri): string
    {
        $string = $uri->getHost();

        if ($uri->getPort() !== null) {
            $string .= ":{$uri->getPort()}";
        }

        return $string;
    }

    private function isExempt(ServerRequestInterface $request): bool
    {
        if (
            $this->bypassPatterns !== []
            && preg_match('/' . implode('|', $this->bypassPatterns) . '/i', $request->getUri()->getPath())
        ) {
            return true;
        }

        $origin = $request->getHeaderLine('Origin');

        if ($origin === '') {
            return false;
        }

        // The request matches a trusted origin.
        return $this->trustedOrigins[$origin] ?? false;
    }
}
