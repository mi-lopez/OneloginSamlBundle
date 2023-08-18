<?php

namespace Symfony\Component\DependencyInjection\Loader\Configurator;

use Doctrine\ORM\EntityManagerInterface;
use Hslavich\OneloginSamlBundle\Controller\SamlController;
use Hslavich\OneloginSamlBundle\EventListener\Security\SamlLogoutListener;
use Hslavich\OneloginSamlBundle\EventListener\User\UserCreatedListener;
use Hslavich\OneloginSamlBundle\EventListener\User\UserModifiedListener;
use Hslavich\OneloginSamlBundle\Security\Authentication\Provider\SamlProvider;
use Hslavich\OneloginSamlBundle\Security\Authentication\Token\SamlTokenFactory;
use Hslavich\OneloginSamlBundle\Security\Firewall\SamlListener;
use Hslavich\OneloginSamlBundle\Security\Http\Authentication\SamlAuthenticationSuccessHandler;
use Hslavich\OneloginSamlBundle\Security\Http\Authenticator\SamlAuthenticator;
use Hslavich\OneloginSamlBundle\Security\User\SamlUserProvider;
use OneLogin\Saml2\Auth;
use Psr\Log\LoggerInterface;
use Symfony\Component\Security\Http\Event\LogoutEvent;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

return static function (ContainerConfigurator $container): void {
    $services = $container->services();

    $services->defaults()
        ->autowire()
        ->autoconfigure();

    $services->load('Hslavich\\OneloginSamlBundle\\Security\\', __DIR__ . '/../../Security/');

    $services->set(Auth::class)
        ->args(['%hslavich_onelogin_saml.settings%']);

    $services->set(SamlController::class);

    $services->set(SamlListener::class)
        ->parent(service('security.authentication.listener.abstract'))
        ->abstract()
        ->call('setOneLoginAuth', [service('cambium.saml.one_login.admin.auth')])
        ->call('setOneLoginCustomerAuth', [service('cambium.saml.one_login.customer.auth')])
        ->call('setEntityManager', [service(EntityManagerInterface::class)]);

    $services->set(SamlAuthenticator::class)
        ->tag('monolog.logger', ['channel' => 'security'])
        ->args([
            /* 0 */ abstract_arg('security.http_utils'),
            /* 1 */ abstract_arg('user provider'),
            /* 2 */ service(Auth::class),
            /* 3 */ abstract_arg('success handler'),
            /* 4 */ abstract_arg('failure handler'),
            /* 5 */ abstract_arg('options'),
            /* 6 */ null,  // user factory
            /* 7 */ service(EventDispatcherInterface::class)->nullOnInvalid(),
            /* 8 */ service(LoggerInterface::class)->nullOnInvalid(),
        ]);

    $services->set(SamlLogoutListener::class)
        ->tag('kernel.event_listener', ['event' => LogoutEvent::class]);

    $services->set(UserCreatedListener::class)
        ->abstract()
        ->args([
            service(EntityManagerInterface::class)->nullOnInvalid(),
            false,  // persist_user
        ]);

    $services->set(UserModifiedListener::class)
        ->abstract()
        ->args([
            service(EntityManagerInterface::class)->nullOnInvalid(),
            false,  // persist_user
        ]);

    $deprecatedAliases = [
        'hslavich_onelogin_saml.user_provider' => SamlUserProvider::class,
        'hslavich_onelogin_saml.saml_provider' => SamlProvider::class,
        'hslavich_onelogin_saml.saml_token_factory' => SamlTokenFactory::class,
        'hslavich_onelogin_saml.saml_authentication_success_handler' => SamlAuthenticationSuccessHandler::class,
        'hslavich_onelogin_saml.saml_listener' => SamlListener::class,
        'hslavich_onelogin_saml.saml_logout_listener' => SamlLogoutListener::class,
    ];
    foreach ($deprecatedAliases as $alias => $class) {
        $services->alias($alias, $class)->deprecate('hslavich/oneloginsaml-bundle', '2.1', '');
    }
};
