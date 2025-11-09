<?php

declare(strict_types=1);

namespace Alexsoft\CrossOriginProtection\Tests\Unit;

use Alexsoft\CrossOriginProtection\CrossOriginProtection;
use Alexsoft\CrossOriginProtection\CrossOriginProtectionMiddleware;
use Alexsoft\CrossOriginProtection\Exception\CrossOriginRequestException;
use Http\Discovery\Psr17Factory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

#[CoversClass(CrossOriginProtectionMiddleware::class)]
final class CrossOriginProtectionMiddlewareTest extends TestCase
{
    #[Test]
    public function it_calls_next_handler_for_safe_request(): void
    {
        $factory = new Psr17Factory();

        $request = $factory->createServerRequest('GET', '/');
        $response = $factory->createResponse(200);

        $requestHandler = new class($response) implements RequestHandlerInterface {
            public function __construct(private readonly ResponseInterface $response) {}

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return $this->response;
            }
        };

        $sut = $this->createSut();

        $this->assertSame(
            $response,
            $sut->process($request, $requestHandler),
        );
    }

    #[Test]
    public function it_throws_exception_for_unsafe_request(): void
    {
        $factory = new Psr17Factory();

        $request = $factory
            ->createServerRequest('POST', '/')
            ->withHeader('Sec-Fetch-Site', 'cross-site');
        $response = $factory->createResponse(200);

        $requestHandler = new class($response) implements RequestHandlerInterface {
            public function __construct(private readonly ResponseInterface $response) {}

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return $this->response;
            }
        };

        $sut = $this->createSut();

        $this->expectException(CrossOriginRequestException::class);
        $this->expectExceptionMessage('cross-origin request detected from Sec-Fetch-Site header');

        $sut->process($request, $requestHandler);
    }

    private function createSut(): CrossOriginProtectionMiddleware
    {
        return new CrossOriginProtectionMiddleware(
            new CrossOriginProtection(),
        );
    }
}
