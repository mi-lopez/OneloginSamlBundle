<?php

namespace Hslavich\OneloginSamlBundle\Security\Authentication\Token;

use Oro\Bundle\SecurityBundle\Authentication\Token\OrganizationAwareTokenInterface;
use Oro\Bundle\SecurityBundle\Authentication\Token\OrganizationAwareTokenTrait;
use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

/**
 * @deprecated since 2.1
 */
class SamlToken extends AbstractToken implements SamlTokenInterface, OrganizationAwareTokenInterface
{
    use OrganizationAwareTokenTrait;

    public function getCredentials()
    {
        return null;
    }
}
