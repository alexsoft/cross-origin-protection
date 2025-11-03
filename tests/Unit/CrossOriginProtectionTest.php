<?php

declare(strict_types=1);

namespace Alexsoft\CrossOriginProtection\Tests\Unit;

use Alexsoft\CrossOriginProtection\CrossOriginProtection;
use Http\Discovery\Psr17Factory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

#[CoversClass(CrossOriginProtection::class)]
final class CrossOriginProtectionTest extends TestCase
{
    #[Test]
    #[DataProvider('skippedMethodsDataProvider')]
    public function check_returns_null_for_methods_where_csrf_is_not_needed(ServerRequestInterface $request): void
    {
        $sut = $this->createSut();

        $this->assertNull($sut->check($request));
    }

    /**
     * @return iterable<string, array{ServerRequestInterface}>
     */
    public static function skippedMethodsDataProvider(): iterable
    {
        $factory = new Psr17Factory();
        $skippedMethods = ['GET', 'HEAD', 'OPTIONS'];

        foreach ($skippedMethods as $method) {
            yield $method => [$factory->createServerRequest($method, '/')];
        }
    }

    private function createSut(): CrossOriginProtection
    {
        return new CrossOriginProtection(
            new Psr17Factory(),
        );
    }
}
