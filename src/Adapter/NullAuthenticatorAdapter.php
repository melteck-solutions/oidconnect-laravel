<?php

namespace Furdarius\OIDConnect\Adapter;

use Furdarius\OIDConnect\Contract\Authenticator;
use Lcobucci\JWT\Token\DataSet;

class NullAuthenticatorAdapter implements Authenticator
{
    /**
     * @param DataSet $claims
     *
     */
    public function authUser(DataSet $claims)
    {}
}
