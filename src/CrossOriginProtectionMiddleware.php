<?php

declare(strict_types=1);

namespace Alexsoft\CrossOriginProtection;

use Alexsoft\CrossOriginProtection\Exception\CrossOriginRequestException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class CrossOriginProtectionMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly CrossOriginProtection $crossOriginProtection,
    ) {}

    /**
     * @throws CrossOriginRequestException
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $crossOriginRequestError = $this->crossOriginProtection->check($request);

        if ($crossOriginRequestError === null) {
            return $handler->handle($request);
        }

        throw new CrossOriginRequestException($crossOriginRequestError->message, 1);
    }
}
