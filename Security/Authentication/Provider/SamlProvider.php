<?php

namespace Hslavich\OneloginSamlBundle\Security\Authentication\Provider;

use Doctrine\ORM\EntityManagerInterface;
use Hslavich\OneloginSamlBundle\Event\UserCreatedEvent;
use Hslavich\OneloginSamlBundle\Event\UserModifiedEvent;
use Hslavich\OneloginSamlBundle\Security\Authentication\Token\SamlTokenFactoryInterface;
use Hslavich\OneloginSamlBundle\Security\Authentication\Token\SamlTokenInterface;
use Hslavich\OneloginSamlBundle\Security\User\SamlUserFactoryInterface;
use Hslavich\OneloginSamlBundle\Security\User\SamlUserInterface;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;
use Synolia\Custom\MigrationBundle\Traits\OrganizationManagerTrait;

/**
 * @deprecated since 2.1
 */
class SamlProvider implements AuthenticationProviderInterface
{
    use OrganizationManagerTrait;

    protected SamlUserFactoryInterface $userFactory;
    protected SamlTokenFactoryInterface $tokenFactory;
    protected UserProviderInterface $customerUserProvider;

    public function __construct(
        protected UserProviderInterface $userProvider,
        protected ?EventDispatcherInterface $eventDispatcher,
        protected EntityManagerInterface $entityManager
    ) {
    }

    public function setUserFactory(SamlUserFactoryInterface $userFactory): void
    {
        $this->userFactory = $userFactory;
    }

    public function setTokenFactory(SamlTokenFactoryInterface $tokenFactory): void
    {
        $this->tokenFactory = $tokenFactory;
    }

    public function setCustomerUserProvider(UserProviderInterface $userProvider): void
    {
        $this->customerUserProvider = $userProvider;
    }

    public function authenticate(TokenInterface $token): TokenInterface
    {
        $user = $this->retrieveUser($token);

        if ($user instanceof SamlUserInterface) {
            $user->setSamlAttributes($token->getAttributes());
            $this->eventDispatcher?->dispatch(new UserModifiedEvent($user));
        }

        $organization = $this->getOrganization($this->entityManager);

        $authenticatedToken = $this->tokenFactory->createToken(
            $user,
            $token->getAttributes(),
            $user->getRoles(),
            $organization
        );
        $authenticatedToken->setAuthenticated(true);

        return $authenticatedToken;
    }

    public function supports(TokenInterface $token): bool
    {
        return $token instanceof SamlTokenInterface;
    }

    protected function retrieveUser($token): UserInterface
    {
        $firewall = $token->getAttributes()['firewall'] ?? null;

        $userProvider = 'frontend' === $firewall
            ? $this->customerUserProvider
            : $this->userProvider;

        return $userProvider->loadUserByUsername($token->getUserIdentifier());
    }

    protected function generateUser($token): UserInterface
    {
        $user = $this->userFactory->createUser($token);
        $this->eventDispatcher?->dispatch(new UserCreatedEvent($user));

        return $user;
    }
}
