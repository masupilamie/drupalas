<?php

/**
 * Drupal authentication source configuration parser.
 *
 * config values that must be present in authsources.php under drupalas:default
 * populated with the default values
 * 'debug' => FALSE,
 * 'drupal_basedir' => '/var/www/drupal',
 * 'drupal_login_url' => 'https://example.com/user',
 * 'drupal_logout_url' => 'https://example.com/user/logout',
 * 'use_cookie' => TRUE,
 * 'cookie_name' => 'SimpleSAMLAuthBridge',
 * 'cookie_secure' => FALSE,
 * 'attributes' => array(
 *                      array('drupaluservar'   => 'uid',  'callit' => 'uid'),
 *                      array('drupaluservar' => 'name', 'callit' => 'cn'),
 *                      array('drupaluservar' => 'mail', 'callit' => 'mail'),
 *                      array('drupaluservar' => 'roles','callit' => 'roles'),
 *                      ),
 *
 */
class sspmod_drupalas_ConfigHelper {

  /**
   * String with the location of this configuration.
   * Used for error reporting.
   */
  private $location;

  /**
   * Whether debug output is enabled.
   *
   * @var bool
   */
  private $debug;

  /**
   * The attributes we should fetch. Can be NULL in which case we will fetch all attributes.
   */
  private $attributes;

  /**
   * The base directory of the drupal site
   */
  private $drupal_dir;

  /**
   * The full drupal login URL (including https:// or https:// without trailing slash at the end
   */
  private $drupal_login_url;

  /**
   * The full drupal logout URL (including https:// or https:// without trailing slash at the end
   */
  private $drupal_logout_url;

  /**
   * The hashing algorithm used in the php hash() function
   */
  private $hash_algorithm;

  /**
   * If a cookie will be used to verify the authentication process
   */
  private $use_cookie;

  /**
   * The name that will be used for the cookie
   */
  private $cookie_name;

  /**
   * If the cookie will be a secure cookie (https:// only)
   */
  private $cookie_secure;

  /**
   * The cookie domain, only used when secure cookie is set to TRUE
   */
  private $cookie_domain;


  /**
   * Constructor for this configuration parser.
   *
   * @param array $config  Configuration.
   * @param string $location  The location of this configuration. Used for error reporting.
   */
  public function __construct($config, $location) {
    assert('is_array($config)');
    assert('is_string($location)');

    $this->location = $location;

    /* Parse configuration. */
    $config = SimpleSAML_Configuration::loadFromArray($config, $location);

    $this->debug = $config->getBoolean('debug', FALSE);
    $this->attributes = $config->getArray('attributes', NULL);
    $this->drupal_dir = $config->getString('drupal_dir');
    $this->drupal_login_url = $config->getString('drupal_login_url', NULL);
    $this->drupal_logout_url = $config->getString('drupal_logout_url', NULL);
    $this->hash_algorithm = $config->getString('hash_algorithm', 'sha256');
    $this->use_cookie = $config->getBoolean('use_cookie', TRUE);
    $this->cookie_name = $config->getString('cookie_name', 'SimpleSAMLAuthBridge');
    $this->cookie_secure = $config->getBoolean('cookie_secure', FALSE);
    $this->cookie_domain = $config->getString('cookie_domain', NULL);
  }

  /**
   * Return the debug
   *
   * @param boolean $debug whether or not debugging should be turned on
   */
  public function getDebug() {
    return $this->debug;
  }

  /**
   * Return the attributes
   *
   * @param array $attributes the array of Drupal attributes to use, NULL means use all available attributes
   */
  public function getAttributes() {
    return $this->attributes;
  }

  /**
   * Return the Drupal base directory
   *
   * @param string $drupal_basedir the base directory of the drupal site
   */
  public function getDrupalDir() {
    return $this->drupal_dir;
  }

  /**
   * Return the drupal login URL
   *
   * @param string $drupal_login_url the full URL to the drupal login page
   */
  public function getDrupalLoginUrl() {
    return $this->drupal_login_url;
  }

  /**
   * Return the drupal logout URL
   *
   * @param string $drupal_logout_url the full URL to the drupal logout page
   */
  public function getDrupalLogoutUrl() {
    return $this->drupal_login_url;
  }

  /**
   * Return hash algorithm used
   *
   * @param string $hash_algorithm which hash function to use in the php hash() function
   */
  public function getHashAlgorithm() {
    return $this->hash_algorithm;
  }

  /**
   * Return use cookie
   *
   * @param boolean $use_cookie whether or not to use a cookie during authentication
   */
  public function getUseCookie() {
    return $this->use_cookie;
  }

  /**
   * Return the cookie name
   *
   * @param string $cookie_name the cookie name to use during authentication
   */
  public function getCookieName() {
    return $this->cookie_name;
  }

  /**
   * Return use secure cookie
   *
   * @param boolean $secure_cookie whether or not to use a secure cookie during authentication
   */
  public function getCookieSecure() {
    return $this->cookie_secure;
  }

  /**
   * Return the cookie domain
   *
   * @param string $cookie_name the cookie name to use during authentication
   */
  public function getCookieDomain() {
    return $this->cookie_domain;
  }





}