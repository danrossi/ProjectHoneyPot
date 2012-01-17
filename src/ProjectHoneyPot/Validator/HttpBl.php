<?php

namespace ProjectHoneyPot\Validator;

use Zend\Validator\AbstractValidator,
    ProjectHoneyPot\Util\ReverseDNSLookup,
    ProjectHoneyPot\Util\ClientIp;


class HttpBl extends AbstractValidator
{
    const API_SERVER = 'dnsbl.httpbl.org';

    const INVALID_VISITOR        = 'visitorInvalid';


    const TYPE_SEARCH_ENGINE = 0;

    protected $visitorTypes = array(
        'Search Engine',
        'Suspicious',
        'Harvester',
        'Suspicious & Harvester',
        'Comment Spammer',
        'Suspicious & Comment Spammer',
        'Harvester & Comment Spammer',
        'Suspicious & Harvester & Comment Spammer'
    );

    /**
     * @var array
     */
    protected $_messageTemplates = array(
        self::INVALID_VISITOR        => "Vistor with host '%value%' of type '%vistorType%' is invalid with score
        '%threatScore%' and last active '%lastActivity%' days ago"
    );

    /**
     * @var array
     */
    protected $_messageVariables = array(
        'threatScore'  => '_threatScore',
        'lastActivity' => '_lastActivity',
        'vistorType'   => '_visitorType'
    );

    /**
     * @var string
     */
    protected $apiKey;

    /**
     * @var int
     */
    protected $minInactivity = 30;

    /**
     * @var int
     */
    protected $maxThreatScore = 50;

    /**
     * @var string
     */
    protected $httpBlHost;

    /**
     * @var string
     */
    protected $_lastActivity;

    /**
     * @var string
     */
    protected $_threatScore;

    /**
     * @var string
     */
    protected $_visitorType;

    /**
     * Sets validator options
     *
     * @param array $options OPTIONAL Options to set, see the manual for all available options
     * @return void
     */
    public function __construct(array $options)
    {
        if (!array_key_exists('apiKey', $options)) {
            throw new Exception\InvalidArgumentException('No Api key provided');
        }
        $this->setApiKey($options['apiKey']);

        if (isset($options['maxThreatScore'])) $this->setMaxThreatScore($options['maxThreatScore']);
        if (isset($options['minInactivity'])) $this->setMinInactivity($options['minInactivity']);
        if (isset($options['testIp'])) $this->setValue($options['testIp']);

        parent::__construct($options);
    }

    /**
     * @param $apiKey
     */
    public function setApiKey($apiKey)
    {
        $this->apiKey = $apiKey;
    }

    /**
     * @return string
     */
    public function getApiKey()
    {
        return $this->apiKey;
    }

    /**
     * @param $maxThreatScore
     */
    public function setMaxThreatScore($maxThreatScore)
    {
        $this->maxThreatScore = $maxThreatScore;
    }

    /**
     * @return int
     */
    public function getMaxThreatScore()
    {
        return $this->maxThreatScore;
    }

    /**
     * @param $minInactivity
     */
    public function setMinInactivity($minInactivity)
    {
        $this->minInactivity = $minInactivity;
    }

    /**
     * @return int
     */
    public function getMinInactivity()
    {
        return $this->minInactivity;
    }

    /**
     * Returns true if and only if $value is a valid IP address
     *
     * @param  mixed $value
     * @return boolean
     */
    public function isValid($value = null)
    {
        $defaultValue = $this->getValue();

        if ($value) {
            $this->setValue($value);
        } else if (!$defaultValue) {
            $this->setValue(ClientIp::getClientIp());
        }

        $dns = $this->getHostForLookup($this->getValue());
        $host = gethostbyname($dns);

        if ($dns == $host) return true;

        $result = explode( '.', $host);
        $code = (int)$result[0];
        $this->_lastActivity = (int)$result[1];
        $this->_threatScore = (int)$result[2];
        $type = (int)$result[3];
        $this->_visitorType = $this->visitorTypes[$type];

        if ($code == '127' && $type > self::TYPE_SEARCH_ENGINE
            && $this->_lastActivity <= $this->getMinInactivity()
            && $this->_threatScore >= $this->getMaxThreatScore()) {
            $this->error(self::INVALID_VISITOR);
            return false;
        }
        return true;
    }

    private function getHostForLookup($ip)
    {
        return sprintf("%s.%s.%s", $this->getApiKey(),
                                    ReverseDNSLookup::reverseLookup($ip),
                                    self::API_SERVER);
    }
}
