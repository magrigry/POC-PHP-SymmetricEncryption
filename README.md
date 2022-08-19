# PHP Encryption POC

## Important ! 
This project is not aimed to be used for production. It has not been made or review by cryptographic 
experts. It's a proof a concept to practice a few things I've learned

### Usage
Encryption can be used for:
- Encrypt sensitive data stored in the database or elsewhere
- Temporarily encrypt data (for example an identifier used to download a file)
  to avoid [Insecure Direct Object References](https://wiki.owasp.org/index.php/Top_10_2013-A4-Insecure_Direct_Object_References)

#### Notes about using encryption to avoid an "Insecure Direct Object References" attack
1. Using encryption in this case is often a workaround. In reality, the problem is often lack of permission check
2. To avoid "replay attack" type attacks (e.g., reusing a previously encrypted identifier
   and pass it back into the URL to download the document in question), session key should be used so that the generated string
   is unique to the session (see the examples with `session_id()`).
3. [This stackexchange topic talks about these topics](https://security.stackexchange.com/questions/34277/avoiding-direct-object-references)

### Example :

```php
require 'Authenticator.php';
require 'AuthenticationFailureException.php';
require 'OpenSSLSymmetricEncryption.php';

$authenticator = new Authenticator(str_repeat(1, 100));
$encryption = new OpenSSLSymmetricEncryption('aes-256-ctr', str_repeat(1, 100), $authenticator);
$encrypted = $encryption->encrypt('test', 'info');
$value = $encryption->decrypt($encrypted, 'info');
var_dump($value);
```

Example to encrypt data valid only during the current session
```php
$encrypted = $encryption->encrypt('test', 'info:' . session_id());
$value = $encryption->decrypt($encrypted, 'info:' . session_id());
```
