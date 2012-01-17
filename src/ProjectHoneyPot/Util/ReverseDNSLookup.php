<?php

namespace ProjectHoneyPot\Util;

class ReverseDNSLookup
{
    public static function reverseLookup($ip)
    {
        return implode('.', array_reverse(explode('.', $ip)));
    }
}
