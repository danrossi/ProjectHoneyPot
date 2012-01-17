<?php
return array(

    'di' => array(
        'instance' => array(
            'alias' => array(
                'projecthoneypot_httpbl_validator'      => 'ProjectHoneyPot\Validator\HttpBl',
            ),
            'projecthoneypot_httpbl_validator' => array(
                'parameters' => array(
                    'options' => array(
                        'apiKey' => '',
                    ),
                ),
            ),
        ),
    ),
);
