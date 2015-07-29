# drupalas - Drupal Authentication Source

A SimpleSAMLphp module connecting to Drupal and using its front page and user base for SAML authentication.


# Under development

This module is still in development, if you want to help me test it, let me know (through github).

# Notes

For this module to function, Drupal must have the "SimpleSAMLphp IdP" module enabled and configured correctly.

# Short installation overview

More detailed installation steps can be found in documents/installation.txt

	*** SimpleSAMLphp part
	-Install SimpleSAMLphp and configure as an Identity Provider.
	-Install (copy) the drupalas module to SimpleSAMLphp IdP modules
		directory.
	-Create a new authentication source in SimpleSAMLphp and
		configure it using the example provided with the module.
		(You need to use the example because there are new
		configuration options needed.)
	-Use the newly created authentication source for the IdP.
		('auth' option in saml20-idp-hosted.php)
	-Use sql or memcache for session store
		(store.type in config.php)

	*** Drupal part
	-Install and enable simplesamlphp_idp module in drupal.
	-Configure simplesamlphp_idp module in drupal.

	*** Testing part
	-Configure a SAML Service Provider to use the just configured
		SimpleSAMLphp Identity Provider.
		(Using another SimpleSAMLphp instance configured as
		Service Provider is a good option for testing.)
	-Use the SAML service provider to check authentication.
