<?php

namespace Hslavich\OneloginSamlBundle\Security\Firewall;

use Doctrine\ORM\EntityManagerInterface;
use Hslavich\OneloginSamlBundle\Security\Authentication\Token\SamlToken;
use OneLogin\Saml2\Auth;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
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

    protected Auth $oneLoginAuth;
    protected Auth $oneLoginCustomerAuth;
    protected EntityManagerInterface $entityManager;
    protected RouterInterface $router;

    public function setOneLoginAuth(Auth $oneLoginAuth): void
    {
        $this->oneLoginAuth = $oneLoginAuth;
    }

    public function setOneLoginCustomerAuth(Auth $oneLoginAuth): void
    {
        $this->oneLoginCustomerAuth = $oneLoginAuth;
    }

    public function setEntityManager(EntityManagerInterface $entityManager): void
    {
        $this->entityManager = $entityManager;
    }

    public function setRouter(RouterInterface $router): void
    {
        $this->router = $router;
    }

    /**
     * Performs authentication.
     *
     * @throws AuthenticationException if the authentication fails
     * @throws \Exception if attribute set by "username_attribute" option not found
     */
    protected function attemptAuthentication(Request $request): TokenInterface|Response|null
    {
        $array = explode('.', trim($request->attributes->get('_firewall_context')));
        $firewallName = end($array);
        switch ($firewallName) {
            case 'main':
                $auth = $this->oneLoginAuth;
                break;
            case 'frontend':
                $auth = $this->oneLoginCustomerAuth;
                break;
            default:
                $message = sprintf('Firewall %s not supported by saml authentication', $firewallName);
                $this->logger?->error(sprintf("[SAML] %s", $message));

                throw new AuthenticationException($message);
        }

        $auth->processResponse();
        if ($auth->getErrors()) {
            $this->logger?->error(sprintf("[SAML] %s", $auth->getLastErrorReason()));

            throw new AuthenticationException($auth->getLastErrorReason());
        }

        $attributes = isset($this->options['use_attribute_friendly_name']) && $this->options['use_attribute_friendly_name']
            ? $auth->getAttributesWithFriendlyName()
            : $auth->getAttributes();
        $attributes['sessionIndex'] = $auth->getSessionIndex();
        $attributes['firewall'] = $firewallName;

        $token = new SamlToken();
        $token->setAttributes($attributes);

        $username = $auth->getNameId();
        if (isset($this->options['username_attribute'])) {
            if (!array_key_exists($this->options['username_attribute'], $attributes)) {
                $this->logger?->error(sprintf("[SAML] Attribute '%s' not found in SAML data. Found attributes: %s", $this->options['username_attribute'], print_r($attributes, true)));

                throw new \RuntimeException(sprintf("Attribute '%s' not found in SAML data", $this->options['username_attribute']));
            }
            $username = $attributes[$this->options['username_attribute']][0];
        }

        $organization = $this->getOrganization($this->entityManager);

        $token->setUser($username);
        $token->setOrganization($organization);

        return $this->authenticationManager->authenticate($token);
    }
}
