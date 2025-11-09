<?php

declare(strict_types=1);

namespace Alexsoft\CrossOriginProtection\Tests\Unit;

use Alexsoft\CrossOriginProtection\CrossOriginRequestError;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(CrossOriginRequestError::class)]
final class CrossOriginRequestErrorTest extends TestCase
{
    #[Test]
    public function it_can_be_created_from_sec_fetch_side_header(): void
    {
        $this->assertEquals(
            'cross-origin request detected from Sec-Fetch-Site header',
            CrossOriginRequestError::fromSecFetchSideHeader()->message,
        );
    }

    #[Test]
    public function it_can_be_created_from_old_browser(): void
    {
        $this->assertEquals(
            'cross-origin request detected, and/or browser is out of date: Sec-Fetch-Site is missing, and Origin does not match Host',
            CrossOriginRequestError::fromOldBrowser()->message,
        );
    }
}
