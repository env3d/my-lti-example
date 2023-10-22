# A basic LTI example

To run, need to setup python env.
Also need to generate private.key and public.key

Use the following:

```
$ openssl genrsa -out private.key 2048
$ openssl rsa -in private.key -pubout -out public.key

```

# Setup on sandbox.moodledemo.net

1. Login as Teacher
1. Go to class, then "More" -> "LTI External Tools"
1. Fill out the following fields:
 - Tool URL: ${APP_URL}/launch/
 - Public key type: RSA Key
 - Public key: $(cat public.key)
 - Initiate login URL: ${APP_URL}/login/
 - Redirection URI: ${APP_URL}/launch/
1. Under "Services"
 - IMS LTI Assignment and Grade Services: Use this service for grade sync and column management

