<?php

namespace App\Auth;

use App\Models\Account;

class SocialLogin
{
    // OAuth callback: resolve the local account for a provider identity.
    public function resolve(string $provider, $socialUser): ?Account
    {
        if ($account = Account::findByProviderId($provider, $socialUser->getId())) {
            return $account;
        }

        if (! ($socialUser->user['email_verified'] ?? false)) {
            return null;
        }

        $account = Account::findByEmail($socialUser->getEmail());

        return $account;
    }
}
