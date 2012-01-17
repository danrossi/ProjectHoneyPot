ProjectHoneyPot
=======
Version 0.0.1 Created by Dan Rossi

Introduction
------------

ProjectHoneyPot is a ZF2 form validation module to be used in conjunction with a form honeypot trap field. The
validator will do a lookup to the Project Honey Pot system and confirm if the visitor IP address is seen as
suspicious, the type of visitor, how many days since it's last activity and it's threat level. The threat level and
inctivity is configurable.

More information available from the Project Honeypot site http://www.projecthoneypot.org/home.php.



Requirements
------------

* [Zend Framework 2](https://github.com/zendframework/zf2) (latest master)


Installation
------------

### Main Setup


1. Clone this project into your `./vendor/` directory and enable it in your
   `application.config.php` file.
2. Copy `./vendor/ZfcUser/config/module.projecthoneypot.config.php.dist` to
   `./config/autoload/module.projecthoneypot.config.php`.

### Post-Install: Adding it to a form

1. Configure a form wrapper and setup the validator via the di config

'di' => array(
        'instance' => array(
            'alias' => array(
                'custom_register_form' => 'Application\Form\Register'
            ),
            'custom_register_form' => array(
                'parameters' => array(
                    'httpBlValidator'    => 'projecthoneypot_httpbl_validator'
                ),
            )
        ),

2. Setup a honeypot field, setting a StringLength validator, together with the Project Honeypot validator.

$form->addElement('text','hp', array(
                    'label' => 'Verify Yourself',
                    'required' => false,
                    'allowEmpty' => false,
                    'class' => 'hp',
                    'decorators' => array('ViewHelper'),
                    'validators' => array(
                        array('StringLength', false, array('max' => 0)),
                        $this->httpBlValidator
                    ),

                    'order'      => -101
                )
            );

3. Inside the form view, configure the css style for the chosen class "hd" to hidden,
so that it is hidden from normal users.

<style>
    .hp {
        display: none;
    }
</style>


Options
-------


The following options are available:

- **apiKey** - Your Api key which is required.
- **maxThreatScore** - The maximum threat score allowed.  Default is 50.
- **minInactivity** - The minimum days of inactivity seen to be active in the database. Default value is 30.
- **testIp** - The test ip addresses used for testing the system out, more information http://www.projecthoneypot
.org/httpbl_api.php.