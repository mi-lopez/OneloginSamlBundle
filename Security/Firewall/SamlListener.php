<?php

namespace Hslavich\OneloginSamlBundle\Security\Firewall;

use Doctrine\ORM\EntityManagerInterface;
use Hslavich\OneloginSamlBundle\Security\Authentication\Token\SamlToken;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Firewall\AbstractAuthenticationListener;
use Synolia\Custom\MigrationBundle\Traits\OrganizationManagerTrait;

/**
 * @deprecated since 2.1
 */
class SamlListener extends AbstractAuthenticationListener
{
    use OrganizationManagerTrait;

    /**
     * @var \OneLogin\Saml2\Auth
     */
    protected $oneLoginAuth;

    /**
     * @var EntityManagerInterface
     */
    protected $entityManager;

    /**
     * @param \OneLogin\Saml2\Auth $oneLoginAuth
     */
    public function setOneLoginAuth(\OneLogin\Saml2\Auth $oneLoginAuth)
    {
        $this->oneLoginAuth = $oneLoginAuth;
    }

    public function setEntityManager(EntityManagerInterface $entityManager)
    {
        $this->entityManager = $entityManager;
    }

    /**
     * Performs authentication.
     *
     * @param Request $request A Request instance
     * @return TokenInterface|Response|null The authenticated token, null if full authentication is not possible, or a Response
     *
     * @throws AuthenticationException if the authentication fails
     * @throws \Exception if attribute set by "username_attribute" option not found
     */
    protected function attemptAuthentication(Request $request)
    {
        $this->oneLoginAuth->processResponse();
        if ($this->oneLoginAuth->getErrors()) {
            if (null !== $this->logger) {
                $this->logger->error($this->oneLoginAuth->getLastErrorReason());
            }
            throw new AuthenticationException($this->oneLoginAuth->getLastErrorReason());
        }

        if (isset($this->options['use_attribute_friendly_name']) && $this->options['use_attribute_friendly_name']) {
            $attributes = $this->oneLoginAuth->getAttributesWithFriendlyName();
        } else {
            $attributes = $this->oneLoginAuth->getAttributes();
        }
        $attributes['sessionIndex'] = $this->oneLoginAuth->getSessionIndex();
        $token = new SamlToken();
        $token->setAttributes($attributes);

        if (isset($this->options['username_attribute'])) {
            if (!array_key_exists($this->options['username_attribute'], $attributes)) {
                if (null !== $this->logger) {
                    $this->logger->error(sprintf("Found attributes: %s", print_r($attributes, true)));
                }
                throw new \RuntimeException(sprintf("Attribute '%s' not found in SAML data", $this->options['username_attribute']));
            }

            $username = $attributes[$this->options['username_attribute']][0];
        } else {
            $username = $this->oneLoginAuth->getNameId();
        }

        $organization = $this->getOrganization($this->entityManager);

        $token->setUser($username);
        $token->setOrganization($organization);

        return $this->authenticationManager->authenticate($token);
    }
}
