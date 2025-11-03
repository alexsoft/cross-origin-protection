<?php

declare(strict_types=1);

use Alexsoft\CrossOriginProtection\CrossOriginProtection;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(CrossOriginProtection::class)]
final class CrossOriginProtectionTest extends TestCase
{
    #[Test]
    public function it_asserts_that_true_is_true(): void
    {
        $this->assertTrue(true);
    }
}
