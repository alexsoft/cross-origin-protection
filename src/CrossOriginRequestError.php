<?php

declare(strict_types=1);

namespace Alexsoft\CrossOriginProtection;

final class CrossOriginRequestError
{
    public function __construct(
        public readonly string $message,
    ) {}

    public static function fromSecFetchSideHeader(): self
    {
        return new self('cross-origin request detected from Sec-Fetch-Site header');
    }

    public static function fromOldBrowser(): self
    {
        return new self(
            'cross-origin request detected, and/or browser is out of date: Sec-Fetch-Site is missing, and Origin does not match Host',
        );
    }
}
