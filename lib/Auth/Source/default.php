<?php

/**
 * This authentication source uses the drupal userbase for authentication.
 *
 * It uses a redirect to the drupal site and back to simplesamlphp during
 * login and logout
 */
class sspmod_drupalas_Auth_Source_default extends SimpleSAML_Auth_Source {

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
   * Constructor for this authentication source.
   *
   * @param array $info  Information about this authentication source.
   * @param array $config  Configuration.
   */
  public function __construct($info, $config) {
    assert('is_array($info)');
    assert('is_array($config)');

    /* Call the parent constructor first, as required by the interface. */
    parent::__construct($info, $config);


    /* Get the configuration for this module */
    $drupalAuthConfig = new sspmod_drupalas_ConfigHelper($config,
      'Authentication source ' . var_export($this->authId, TRUE));

    $this->debug       = $drupalAuthConfig->getDebug();
    $this->attributes  = $drupalAuthConfig->getAttributes();
    $this->drupal_dir = $drupalAuthConfig->getDrupalDir();
    $this->drupal_login_url = $drupalAuthConfig->getDrupalLoginUrl();
    $this->drupal_logout_url = $drupalAuthConfig->getDrupalLogoutURL();
    $this->hash_algorithm = $drupalAuthConfig->getHashAlgorithm();
    $this->use_cookie = $drupalAuthConfig->getUseCookie();
    $this->cookie_name = $drupalAuthConfig->getCookieName();
    $this->cookie_secure = $drupalAuthConfig->getCookieSecure();
    $this->cookie_domain = $drupalAuthConfig->getCookieDomain();

    $sspIdpConfig = SimpleSAML_Configuration::getInstance();
    $this->cookie_path = '/' . $sspIdpConfig->getValue('baseurlpath');
    $this->secretsalt = $sspIdpConfig->getValue('secretsalt');

    if (!defined('DRUPAL_ROOT')) {
      define('DRUPAL_ROOT', $drupalAuthConfig->getDrupalDir());
    }

    $d = getcwd();
    chdir(DRUPAL_ROOT);

    /* Include the Drupal bootstrap */
    //require_once(DRUPAL_ROOT.'/includes/common.inc');
    require_once(DRUPAL_ROOT.'/includes/bootstrap.inc');
    require_once(DRUPAL_ROOT.'/includes/file.inc');

    /* Using DRUPAL_BOOTSTRAP_FULL means that SimpleSAMLphp must use an session storage
     * mechanism other than phpsession (see: store.type in config.php).
     */
    drupal_bootstrap(DRUPAL_BOOTSTRAP_FULL);

    // we need to be able to call Drupal user function so we load some required modules
    drupal_load('module', 'system');
    drupal_load('module', 'user');
    drupal_load('module', 'field');

    chdir($d);
  }

  /**
   * Retrieve attributes for the user.
   *
   * @return array|NULL  The user's attributes, or NULL if the user isn't authenticated.
   */
  private function getUser($state) {

    //make sure we start with a clean slate
    $attributes = NULL;
    $drupal_uid = NULL;
    $drupal_user = NULL;

    //first make sure we received a state
    if (!is_array($state)) {
      throw new SimpleSAML_Error_Exception('State was lost while checking authentication');
    }

    //check if the key value exist, otherwise throw exception
    if ( (isset($_GET['state']) && $_GET['state']) && (isset($_GET['key']) && $_GET['key']) ) {

      //check if the session salt exists, otherwist show exception
      if (isset($state['drupal_login_salt']) && $state['drupal_login_salt']) {

        //check if the drupal uid exists, otherwise show exception
        if (isset($state['drupal_uid']) && $state['drupal_uid']) {

          //now we can check if the hash is correct, otherwise show exception
          if ($_GET['key'] == hash($this->hash_algorithm, $state['drupal_login_salt'] . $state['drupal_uid'])) {

            //check if settings dictate the use of a cookie
            if ($this->use_cookie == TRUE) {

              //we are using a cookie

              //check if the cookie is present
              if(isset($_COOKIE[$this->cookie_name]) && $_COOKIE[$this->cookie_name]) {

                //cookie is present

                //lets check the cookie hash
                if ($_COOKIE[$this->cookie_name] == hash($this->hash_algorithm, $this->secretsalt . $state['drupal_uid'] . $state['drupal_cookie_salt'])) {

                  //cookie is correct, lets delete it and confirm authentication
                  if ($this->cookie_secure == TRUE) {

                    //deleting the cookie by setting a new empty one with a negative time validity
                    //we need to override with a secure cookie
                    setcookie($this->cookie_name, '', -3600, $this->cookie_path, $this->cookie_domain, TRUE);

                  } else {

                    //deleting the cookie by setting a new empty one with a negative time validity
                    setcookie($this->cookie_name, '', -3600, $this->cookie_path);

                  }

                  //set drupal_uid value, this indicates that the user successfully authenticated
                  $drupal_uid = $state['drupal_uid'];

                } else {

                  //cookie is incorrect, lets delete it anyway
                  if ($this->cookie_secure == TRUE) {

                    //deleting the cookie by setting a new empty one with a negative time validity
                    //we need to override with a secure cookie
                    setcookie($this->cookie_name, '', -3600, $this->cookie_path, $this->cookie_domain, TRUE);

                  } else {

                    //deleting the cookie by setting a new empty one with a negative time validity
                    setcookie($this->cookie_name, '', -3600, $this->cookie_path);

                  }

                  //show invalid cookie hash exception
                  throw new SimpleSAML_Error_Exception('Given cookie key is invalid, someone is tampering!');

                }

              } else {

                //show no cookie found exception
                throw new SimpleSAML_Error_Exception('No cookie found');

              }

            } else {

              //no cookie is being used, so authentication is compleet

              //set drupal_uid value, this indicates that the user successfully authenticated
              $drupal_uid = $state['drupal_uid'];

            }

        } else {

            //show invalid hash exception
            throw new SimpleSAML_Error_Exception('Given key is invalid, someone is tampering!');
          }

        } else {

          //show drupal uid missing exception
          throw new SimpleSAML_Error_Exception('Something went wrong: drupal uid is missing');

        }

      } else {

        //show session salt missing exception
        throw new SimpleSAML_Error_Exception('Something went wrong: salt is missing');

      }

    } else {

      //show state and or key missing exception
      throw new SimpleSAML_Error_Exception('Something went wrong: key value is missing');

    }


    //if drupal_uid has a value the authentication has succeeded and we can continue loading the user attributes
    if (!empty($drupal_uid)) {

      //save current directory and change directory so drupal functions work (we use user_load)
      $d = getcwd();
      chdir(DRUPAL_ROOT);

      //Get the user object from Drupal
      $drupal_user = user_load($drupal_uid);

      //change directory back to previously saved directory
      chdir($d);

      //make sure the user object is loaded




      // get all the attributes out of the user object
      $userAttrs = get_object_vars($drupal_user);

      // define some variables to use as arrays
      $userAttrNames = null;
      $attributes = null;

      // figure out which attributes to include
      if(NULL == $this->attributes){
        $userKeys = array_keys($userAttrs);

        // populate the attribute naming array
        foreach($userKeys as $userKey){
          $userAttrNames[$userKey] = $userKey;
        }

      }else{
        // populate the array of attribute keys
        // populate the attribute naming array
        foreach($this->attributes as $confAttr){

          $userKeys[] = $confAttr['drupaluservar'];
          $userAttrNames[$confAttr['drupaluservar']] = $confAttr['callit'];

        }

      }

      // an array of the keys that should never be included
      // (e.g., pass)
      $skipKeys = array('pass');

      // package up the user attributes
      foreach($userKeys as $userKey){

        // skip any keys that should never be included
        if(!in_array($userKey, $skipKeys)){

          if(   is_string($userAttrs[$userKey])
            || is_numeric($userAttrs[$userKey])
            || is_bool($userAttrs[$userKey])    ){

            $attributes[$userAttrNames[$userKey]] = array($userAttrs[$userKey]);

          }elseif(is_array($userAttrs[$userKey])){

            // if the field is a field module field, special handling is required
            if(substr($userKey,0,6) == 'field_'){
              $attributes[$userAttrNames[$userKey]] = array($userAttrs[$userKey]['und'][0]['safe_value']);
            }else{
              // otherwise treat it like a normal array
              $attributes[$userAttrNames[$userKey]] = $userAttrs[$userKey];
            }

          }

        }

      }

    }

    //this will be null if authentication failed and an array if authentication succeeded
    return $attributes;

  }

  /**
   * Log in using an external authentication helper.
   *
   * @param array &$state  Information about the current authentication.
   */
  public function authenticate(&$state) {
    assert('is_array($state)');

    /**
     * First we add the configured authentication source identifier of this
     * authentication source to the state array,
     * so that we know where to resume.
     */
    $state['drupalas_AuthID'] = $this->authId;

    /**
     * We need to save the $state-array, so that we can resume the
     * login process after authentication.
     *
     * Note the second parameter to the saveState-function. This is a
     * unique identifier for where the state was saved, and must be used
     * again when we retrieve the state.
     *
     * The reason for it is to prevent
     * attacks where the user takes a $state-array saved in one location
     * and restores it in another location, and thus bypasses steps in
     * the authentication process.
     */
    $stateId = SimpleSAML_Auth_State::saveState($state, 'drupalas_login_stage_one', TRUE);

    /**
     * Now we generate an URL the user should return to after authentication.
     * We assume that whatever authentication page we send the user to has an
     * option to return the user to a specific page afterwards.
     */
    $returnTo = SimpleSAML_Module::getModuleURL('drupalas/resumeLogin.php');

    /**
     * The redirect to the authentication page.
     *
     * Note the 'ReturnTo' parameter. This must most likely be replaced with
     * the real name of the parameter for the login page.
     */
    SimpleSAML_Utilities::redirect($this->drupal_login_url, array(
      'saml_login' => 'true',
      'state' => $stateId,
      'returnTo' => $returnTo,
    ));

  }


  /**
   * Resume authentication process.
   *
   * This function resumes the authentication process after the user has
   * been authenticated by drupal
   *
   * @param array &$state  The authentication state.
   */
  public static function resumeLogin() {

    /**
     * First we need to restore the $state-array. We should have the identifier for
     * it in the 'State' request parameter.
     */
    if (!isset($_GET['state'])) {
      throw new SimpleSAML_Error_Exception('Something went wrong: state value is missing');
    }
    $stateId_get = (string)$_GET['state'];

    /**
     * Once again, note the second parameter to the loadState function. This must
     * match the string we used in the saveState-call in hook_user_login() in drupal
     */
    $state = SimpleSAML_Auth_State::loadState($stateId_get, 'drupalas_login_stage_two');

    /**
     * Now we have the $state-array, and can use it to locate the authentication
     * source.
     */
    $source = SimpleSAML_Auth_Source::getById($state['drupalas_AuthID']);
    if ($source === NULL) {
      /*
       * The only way this should fail is if we remove or rename the authentication source
       * while the user is at the login page.
       */
      throw new SimpleSAML_Error_Exception('Could not find authentication source with id ' . $state['drupalas_AuthID']);
    }

    /**
     * Make sure that we haven't switched the source type while the
     * user was at the authentication page. This can only happen if we
     * change config/authsources.php while an user is logging in.
     */
    if (! ($source instanceof self)) {
      throw new SimpleSAML_Error_Exception('Authentication source type changed.');
    }

    /**
     * OK, now we know that our current state is sane. Time to actually log the user in.
     *
     * First we check that the user is acutally logged in, and didn't simply skip the login page.
     */
    $attributes = $source->getUser($state);
    if ($attributes === NULL) {
      /*
       * The user isn't authenticated.
       *
       * Here we simply throw an exception, but we could also redirect the user back to the
       * login page.
       */
      throw new SimpleSAML_Error_Exception('User not authenticated after login page.');
    }

    /**
     * So, we have a valid user. Time to resume the authentication process where we
     * paused it in the authenticate()-function above.
     */
    $state['Attributes'] = $attributes;
    SimpleSAML_Auth_Source::completeAuth($state);

    /**
     * The completeAuth-function never returns, so we never get this far.
     */
    assert('FALSE');
  }

  /**
   * This function is called when the user start a logout operation, for example
   * by logging out of a SP that supports single logout.
   *
   * @param array &$state  The logout state array.
   */
  public function logout(&$state) {
    assert('is_array($state)');

    //session_start not called before. Do it here.
    //no session start needed as everything seems to work fine without?
    /*if (!session_id()) {
      session_start();
    }*/

    $stateId = SimpleSAML_Auth_State::saveState($state, 'drupalas_logout');

    SimpleSAML_Utilities::redirect($this->drupal_logout_url, array(
      'saml_logout' => 'true',
      'state' => $stateId,
    ));

  }

}