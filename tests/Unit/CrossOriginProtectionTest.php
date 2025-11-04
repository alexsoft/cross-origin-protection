<?php

declare(strict_types=1);

namespace Alexsoft\CrossOriginProtection\Tests\Unit;

use Alexsoft\CrossOriginProtection\CrossOriginProtection;
use Alexsoft\CrossOriginProtection\CrossOriginRequestError;
use Alexsoft\CrossOriginProtection\Exception\InvalidArgumentException;
use Http\Discovery\Psr17Factory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;

#[CoversClass(CrossOriginProtection::class)]
final class CrossOriginProtectionTest extends TestCase
{
    #[Test]
    #[DataProvider('safeRequestDataProvider')]
    public function check_returns_null_for_safe_requests(ServerRequestInterface $request): void
    {
        $sut = $this->createSut();

        $this->assertNull($sut->check($request));
    }

    #[Test]
    #[DataProvider('unsafeSecFetchSiteRequestDataProvider')]
    public function check_returns_from_sec_fetch_side_header_error_for_unsafe_request_from_sec_fetch_site_header(ServerRequestInterface $request): void
    {
        $sut = $this->createSut();

        $this->assertEquals(
            new CrossOriginRequestError('cross-origin request detected from Sec-Fetch-Site header'),
            $sut->check($request),
        );
    }

    #[Test]
    public function check_considers_request_with_missing_sec_fetch_site_and_origin_headers_safe(): void
    {
        $sut = $this->createSut();

        $request = (new Psr17Factory())
            ->createServerRequest('POST', '/');

        $this->assertNull($sut->check($request));
    }

    #[Test]
    #[DataProvider('unsafeOldBrowserRequestDataProvider')]
    public function check_returns_from_old_browser_error_for_unsafe_request_with_different_uri_and_origin_host(ServerRequestInterface $request): void
    {
        $sut = $this->createSut();

        $this->assertEquals(
            new CrossOriginRequestError('cross-origin request detected, and/or browser is out of date: Sec-Fetch-Site is missing, and Origin does not match Host'),
            $sut->check($request),
        );
    }

    #[Test]
    public function cannot_add_empty_bypass_pattern(): void
    {
        $sut = $this->createSut();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Regex must not be empty.');

        $sut->addInsecureBypassPattern('');
    }

    #[Test]
    #[DataProvider('invalidTrustedOriginDataProvider')]
    public function cannot_add_invalid_trusted_origin(
        string|UriInterface $uri,
        string $expectedExceptionMessage,
    ): void {
        $sut = $this->createSut();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($expectedExceptionMessage);

        $sut->addTrustedOrigin($uri);
    }

    /**
     * @return iterable<string, array{ServerRequestInterface}>
     */
    public static function safeRequestDataProvider(): iterable
    {
        $factory = new Psr17Factory();

        $skippedMethods = ['GET', 'HEAD', 'OPTIONS'];

        foreach ($skippedMethods as $method) {
            yield "Method: {$method}" => [$factory->createServerRequest($method, '/')];
        }

        $serverRequest = $factory->createServerRequest('POST', '/');

        $secFetchSiteHeaders = ['none', 'same-origin'];

        foreach ($secFetchSiteHeaders as $header) {
            yield "Sec-Fetch-Site: {$header}" => [$serverRequest->withHeader('Sec-Fetch-Site', $header)];
        }

        yield 'Origin and URI host are the same, without port' => [
            $factory
                ->createServerRequest('POST', 'https://example.com/documents')
                ->withHeader('Origin', 'https://example.com'),
        ];

        yield 'Origin and URI host are the same, with port' => [
            $factory
                ->createServerRequest('POST', 'https://example.com:8080/documents')
                ->withHeader('Origin', 'https://example.com:8080'),
        ];
    }

    /**
     * @return iterable<string, array{ServerRequestInterface}>
     */
    public static function unsafeSecFetchSiteRequestDataProvider(): iterable
    {
        $serverRequest = (new Psr17Factory())
            ->createServerRequest('POST', '/');

        $secFetchSiteHeaders = ['cross-site', 'cross-origin'];

        foreach ($secFetchSiteHeaders as $header) {
            yield "Sec-Fetch-Site: {$header}" => [$serverRequest->withHeader('Sec-Fetch-Site', $header)];
        }
    }

    /**
     * @return iterable<string, array{ServerRequestInterface}>
     */
    public static function unsafeOldBrowserRequestDataProvider(): iterable
    {
        $factory = new Psr17Factory();

        yield 'Origin and URI host are not the same, without port' => [
            $factory
                ->createServerRequest('POST', 'https://example.com/documents')
                ->withHeader('Origin', 'https://example2.com'),
        ];

        yield 'Origin and URI host are not the same, with port, domain is different' => [
            $factory
                ->createServerRequest('POST', 'https://example.com:8080/documents')
                ->withHeader('Origin', 'https://example2.com:8080'),
        ];

        yield 'Origin and URI host are not the same, with port, port is different' => [
            $factory
                ->createServerRequest('POST', 'https://example.com:8080/documents')
                ->withHeader('Origin', 'https://example.com:9999'),
        ];
    }

    public static function invalidTrustedOriginDataProvider(): iterable
    {
        $factory = new Psr17Factory();

        yield 'Origin without scheme, string' => [
            'uri' => 'example.com:8080',
            'expectedExceptionMessage' => "Invalid origin example.com:8080: scheme is required",
        ];
        yield 'Origin without scheme, UriInterface' => [
            'uri' => $factory->createUri('example.com:8080'),
            'expectedExceptionMessage' => "Invalid origin example.com:8080: scheme is required",
        ];

        // UriInterface case is impossible as this URI is not parseable
        yield 'Origin without host, string' => [
            'uri' => 'https://:8080',
            'expectedExceptionMessage' => "Invalid origin https://:8080: could not parse",
        ];

        yield 'Origin with path, string' => [
            'uri' => 'https://example.com:8080/documents',
            'expectedExceptionMessage' => "Invalid origin https://example.com:8080/documents: path, query, and fragment are not allowed",
        ];
        yield 'Origin with path, UriInterface' => [
            'uri' => $factory->createUri('https://example.com:8080/documents'),
            'expectedExceptionMessage' => "Invalid origin https://example.com:8080/documents: path, query, and fragment are not allowed",
        ];

        yield 'Origin with query, string' => [
            'uri' => 'https://example.com:8080?client=test',
            'expectedExceptionMessage' => "Invalid origin https://example.com:8080?client=test: path, query, and fragment are not allowed",
        ];
        yield 'Origin with query, UriInterface' => [
            'uri' => $factory->createUri('https://example.com:8080?client=test'),
            'expectedExceptionMessage' => "Invalid origin https://example.com:8080?client=test: path, query, and fragment are not allowed",
        ];

        yield 'Origin with fragment, string' => [
            'uri' => 'https://example.com:8080#fragment1',
            'expectedExceptionMessage' => "Invalid origin https://example.com:8080#fragment1: path, query, and fragment are not allowed",
        ];
        yield 'Origin with fragment, UriInterface' => [
            'uri' => $factory->createUri('https://example.com:8080#fragment1'),
            'expectedExceptionMessage' => "Invalid origin https://example.com:8080#fragment1: path, query, and fragment are not allowed",
        ];
    }

    private function createSut(): CrossOriginProtection
    {
        return new CrossOriginProtection(
            new Psr17Factory(),
        );
    }
}
