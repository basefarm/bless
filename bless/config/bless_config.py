"""
.. module: bless.config.bless_config
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
import configparser
import base64
import os
import re
import zlib
import bz2
import boto3
from botocore.exceptions import ClientError
import logging

# Added for key creation
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from datetime import datetime, timedelta
import pytz

BLESS_OPTIONS_SECTION = 'Bless Options'
CERTIFICATE_VALIDITY_BEFORE_SEC_OPTION = 'certificate_validity_before_seconds'
CERTIFICATE_VALIDITY_AFTER_SEC_OPTION = 'certificate_validity_after_seconds'
CERTIFICATE_VALIDITY_SEC_DEFAULT = 60 * 2

ENTROPY_MINIMUM_BITS_OPTION = 'entropy_minimum_bits'
ENTROPY_MINIMUM_BITS_DEFAULT = 2048

RANDOM_SEED_BYTES_OPTION = 'random_seed_bytes'
RANDOM_SEED_BYTES_DEFAULT = 256

LOGGING_LEVEL_OPTION = 'logging_level'
LOGGING_LEVEL_DEFAULT = 'INFO'

TEST_USER_OPTION = 'test_user'
TEST_USER_DEFAULT = None

CERTIFICATE_EXTENSIONS_OPTION = 'certificate_extensions'
# These are the the ssh-keygen default extensions:
CERTIFICATE_EXTENSIONS_DEFAULT = 'permit-X11-forwarding,' \
                                 'permit-agent-forwarding,' \
                                 'permit-port-forwarding,' \
                                 'permit-pty,' \
                                 'permit-user-rc'

BLESS_CA_SECTION = 'Bless CA'
CA_KEY_STORE_TYPE_OPTION = 'ca_key_store_type'
CA_KEY_STORE_TYPE_OPTION_DEFAULT = 'local'
CA_KEY_PREFIX_OPTION = 'ca_key_prefix'
CA_KEY_VALIDITY_OPTION = 'ca_key_validity'
CA_KEY_SIZE_OPTION = 'ca_key_size'
CA_KEY_SIZE_OPTION_DEFAULT = '2048'

CA_PRIVATE_KEY_FILE_OPTION = 'ca_private_key_file'


CA_PRIVATE_KEY_KEY_ID_OPTION = 'ca_private_key_key_id'
CA_PRIVATE_KEY_OPTION = 'ca_private_key'
CA_PRIVATE_KEY_COMPRESSION_OPTION = 'ca_private_key_compression'
CA_PRIVATE_KEY_COMPRESSION_OPTION_DEFAULT = None

CA_PASSPHRASE_KEY_ID_OPTION = 'ca_passphrase_key_id'

CA_PUBLIC_KEY_KEY_ID_OPTION = 'ca_public_key_key_id'

REGION_PASSWORD_OPTION_SUFFIX = '_password'

KMSAUTH_SECTION = 'KMS Auth'
KMSAUTH_USEKMSAUTH_OPTION = 'use_kmsauth'
KMSAUTH_USEKMSAUTH_DEFAULT = False

KMSAUTH_KEY_ID_OPTION = 'kmsauth_key_id'
KMSAUTH_KEY_ID_DEFAULT = ''

KMSAUTH_REMOTE_USERNAMES_ALLOWED_OPTION = 'kmsauth_remote_usernames_allowed'
KMSAUTH_REMOTE_USERNAMES_ALLOWED_OPTION_DEFAULT = None

KMSAUTH_SERVICE_ID_OPTION = 'kmsauth_serviceid'
KMSAUTH_SERVICE_ID_DEFAULT = None

USERNAME_VALIDATION_OPTION = 'username_validation'
USERNAME_VALIDATION_DEFAULT = 'useradd'

REMOTE_USERNAMES_VALIDATION_OPTION = 'remote_usernames_validation'
REMOTE_USERNAMES_VALIDATION_DEFAULT = 'principal'

VALIDATE_REMOTE_USERNAMES_AGAINST_IAM_GROUPS_OPTION = 'kmsauth_validate_remote_usernames_against_iam_groups'
VALIDATE_REMOTE_USERNAMES_AGAINST_IAM_GROUPS_DEFAULT = False
BLESS_IAM_SECTION = 'Bless IAM'
IAM_GROUPS = 'IAM Groups'

IAM_GROUP_NAME_VALIDATION_FORMAT_OPTION = 'kmsauth_iam_group_name_format'
IAM_GROUP_NAME_VALIDATION_FORMAT_DEFAULT = 'ssh-{}'

REMOTE_USERNAMES_BLACKLIST_OPTION = 'remote_usernames_blacklist'
REMOTE_USERNAMES_BLACKLIST_DEFAULT = None


class BlessConfig(configparser.RawConfigParser, object):
    def __init__(self, aws_region, config_file):
        """
        Parses the BLESS config file, and provides some reasonable default values if they are
        absent from the config file.

        The [Bless Options] section is entirely optional, and has defaults.

        The [Bless CA] section is required.
        :param aws_region: The AWS Region BLESS is deployed to.
        :param config_file: Path to the connfig file.
        """
        self.aws_region = aws_region
        defaults = {CERTIFICATE_VALIDITY_BEFORE_SEC_OPTION: CERTIFICATE_VALIDITY_SEC_DEFAULT,
                    CERTIFICATE_VALIDITY_AFTER_SEC_OPTION: CERTIFICATE_VALIDITY_SEC_DEFAULT,
                    ENTROPY_MINIMUM_BITS_OPTION: ENTROPY_MINIMUM_BITS_DEFAULT,
                    RANDOM_SEED_BYTES_OPTION: RANDOM_SEED_BYTES_DEFAULT,
                    LOGGING_LEVEL_OPTION: LOGGING_LEVEL_DEFAULT,
                    TEST_USER_OPTION: TEST_USER_DEFAULT,
                    KMSAUTH_SERVICE_ID_OPTION: KMSAUTH_SERVICE_ID_DEFAULT,
                    KMSAUTH_KEY_ID_OPTION: KMSAUTH_KEY_ID_DEFAULT,
                    KMSAUTH_REMOTE_USERNAMES_ALLOWED_OPTION: KMSAUTH_REMOTE_USERNAMES_ALLOWED_OPTION_DEFAULT,
                    KMSAUTH_USEKMSAUTH_OPTION: KMSAUTH_USEKMSAUTH_DEFAULT,
                    CERTIFICATE_EXTENSIONS_OPTION: CERTIFICATE_EXTENSIONS_DEFAULT,
                    USERNAME_VALIDATION_OPTION: USERNAME_VALIDATION_DEFAULT,
                    REMOTE_USERNAMES_VALIDATION_OPTION: REMOTE_USERNAMES_VALIDATION_DEFAULT,
                    VALIDATE_REMOTE_USERNAMES_AGAINST_IAM_GROUPS_OPTION: VALIDATE_REMOTE_USERNAMES_AGAINST_IAM_GROUPS_DEFAULT,
                    IAM_GROUP_NAME_VALIDATION_FORMAT_OPTION: IAM_GROUP_NAME_VALIDATION_FORMAT_DEFAULT,
                    REMOTE_USERNAMES_BLACKLIST_OPTION: REMOTE_USERNAMES_BLACKLIST_DEFAULT,
                    CA_PRIVATE_KEY_COMPRESSION_OPTION: CA_PRIVATE_KEY_COMPRESSION_OPTION_DEFAULT,
                    CA_KEY_SIZE_OPTION: CA_KEY_SIZE_OPTION_DEFAULT,
                    CA_KEY_STORE_TYPE_OPTION: CA_KEY_STORE_TYPE_OPTION_DEFAULT
                    }
        configparser.RawConfigParser.__init__(self, defaults=defaults)
        self.read(config_file)

        if not self.has_section(BLESS_CA_SECTION):
            self.add_section(BLESS_CA_SECTION)

        if not self.has_section(BLESS_OPTIONS_SECTION):
            self.add_section(BLESS_OPTIONS_SECTION)

        if not self.has_section(BLESS_IAM_SECTION):
            self.add_section(BLESS_IAM_SECTION)

        if not self.has_section(KMSAUTH_SECTION):
            self.add_section(KMSAUTH_SECTION)

        self.ca_store_type = self.get(BLESS_CA_SECTION, CA_KEY_STORE_TYPE_OPTION).lower()

        if not self.has_option(BLESS_CA_SECTION, self.aws_region + REGION_PASSWORD_OPTION_SUFFIX):
            if not self.has_option(BLESS_CA_SECTION, 'default' + REGION_PASSWORD_OPTION_SUFFIX) and self.ca_store_type != 'ssm':
                raise ValueError("No Region Specific And No Default Password Provided.")
            self.kms = boto3.client('kms')

        logging_level = self.get(BLESS_OPTIONS_SECTION, LOGGING_LEVEL_OPTION)
        numeric_level = getattr(logging, logging_level.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: {}'.format(logging_level))
        self.logger = logging.getLogger()
        self.logger.setLevel(numeric_level)
        if self.ca_store_type == 'ssm':
            # Privat, public and passphrase to be stored in SSM
            self.ca_key_validity = int(self.get(BLESS_CA_SECTION, CA_KEY_VALIDITY_OPTION))
            self.ca_private_key_key_id = self.get(BLESS_CA_SECTION, CA_PRIVATE_KEY_KEY_ID_OPTION)
            self.ca_passphrase_key_id = self.get(BLESS_CA_SECTION, CA_PASSPHRASE_KEY_ID_OPTION)
            self.ca_public_key_key_id = self.get(BLESS_CA_SECTION, CA_PUBLIC_KEY_KEY_ID_OPTION)
            self.ca_key_size = int(self.get(BLESS_CA_SECTION, CA_KEY_SIZE_OPTION))
            self.ca_key_prefix = self.get(BLESS_CA_SECTION, CA_KEY_PREFIX_OPTION)

            if self.ca_passphrase_key_id is None:
                raise ValueError("Missing the passphrase KMS key ID for encryption (ca_passphrase_key_id).")
            self.ssm = boto3.client('ssm')
            self.delta = timedelta(seconds=self.ca_key_validity)
            self.epoch = datetime(1970, 1, 1, tzinfo=pytz.utc)

            # Pre-fill the cache
            self._cache()

        self.logger.info('Finished BlessConfig initialization')

        # TODO: Removing these maks some tests fail, but we do not have the need for this any more
        # We need to rebuild the tests to allow the password to be stored in SSM
        # if not self.has_option(BLESS_CA_SECTION, self.aws_region + REGION_PASSWORD_OPTION_SUFFIX):
        # if not self.has_option(BLESS_CA_SECTION, 'default' + REGION_PASSWORD_OPTION_SUFFIX):
        # raise ValueError("No Region Specific And No Default Password Provided.")

    def getpassword(self):
        """
        Returns the correct encrypted password based off of the aws_region.
        :return: A Base64 encoded KMS CiphertextBlob.
        """
        if hasattr(self, 'encrypted_password') and self.encrypted_password is not None:
            self.logger.info('GetPassword: Returning encrypted password')
            return self.encrypted_password.encode('ascii')
        if self.has_option(BLESS_CA_SECTION, self.aws_region + REGION_PASSWORD_OPTION_SUFFIX):
            return self.get(BLESS_CA_SECTION, self.aws_region + REGION_PASSWORD_OPTION_SUFFIX)
        return self.get(BLESS_CA_SECTION, 'default' + REGION_PASSWORD_OPTION_SUFFIX)

    def getkmsauthkeyids(self):
        """
        Returns a list of kmsauth keys used for validation (so a key generated
        in one region can validate in another).
        :return: A list of kmsauth key ids
        """
        return list(map(str.strip, self.get(KMSAUTH_SECTION, KMSAUTH_KEY_ID_OPTION).split(',')))

    def getpublickeys(self):
        """
        Return all the public keys
        """
        if self.ca_store_type == 'ssm':
            if not self._key_ok():
                self._cache()
            if not hasattr(self, 'id') or self.id is None:
                # Give up, do'nt have any key's cached.
                self.logger.error("getpublickeys: No ID returned by cache, giving up.")
                return None
            self.logger.info("getpublickeys: Getting keys starting from ID: {}".format(self.id))
            key1 = self._get_params(self.id)
            key2 = self._get_params(self.id + 1)
            ts1 = (key1['ts'] + self.delta - self.epoch).total_seconds()
            ts2 = (key2['ts'] + self.delta - self.epoch).total_seconds()
            self.logger.info('SENDING KEY1 DELTA: {}'.format(str(ts1)))
            return [
                {'id': self.id, 'key': key1['public'], 'valid': ts1},
                {'id': self.id + 1, 'key': key2['public'], 'valid': ts2}]
        return None

    def getprivatekey(self):
        """
        Get the private key used for signing the users key. The function will look for the
        key in the following places:
          - in the SSM parameter store
          - in the configuration file
          - in a local file in the deployed lambda function
        If SSM is configured, it will be used over any key in the configuration file.
        If SSM is configured, but no key is present in SSM, a new key
        will be created and uploaded to SSM. Subsequent Bless invocations will then use
        this certificate. The passphrase protecting the certificate will also be uploaded,
        encrypted using KMS. The public part of the key is uploaded to a separate
        SSM parameter path.
        """
        compression = self.get(BLESS_CA_SECTION, CA_PRIVATE_KEY_COMPRESSION_OPTION)

        if self.ca_store_type == 'ssm':
            self._cache()
            self.logger.info('GetPrivateKey: Returning private key.')
            return self.key_priv.encode('ascii')
        else:
            if self.has_option(BLESS_CA_SECTION, CA_PRIVATE_KEY_OPTION):
                return self._decompress(base64.b64decode(self.get(BLESS_CA_SECTION, CA_PRIVATE_KEY_OPTION)), compression)

        ca_private_key_file = self.get(BLESS_CA_SECTION, CA_PRIVATE_KEY_FILE_OPTION)

        # read the private key .pem
        with open(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, ca_private_key_file), 'rb') as f:
            return self._decompress(f.read(), compression)

    def has_option(self, section, option):
        """
        Checks if an option exists.

        This will search in both the environment variables and in the config file
        :param section: The section to search in
        :param option: The option to check
        :return: True if it exists, False otherwise
        """
        environment_key = self._environment_key(section, option)
        if environment_key in os.environ:
            return True
        else:
            return super(BlessConfig, self).has_option(section, option)

    def get(self, section, option, **kwargs):
        """
        Gets a value from the configuration.

        Checks the environment  before looking in the config file.
        :param section: The config section to look in
        :param option: The config option to look at
        :return: The value of the config option
        """
        environment_key = self._environment_key(section, option)
        output = os.environ.get(environment_key, None)
        if output is None:
            output = super(BlessConfig, self).get(section, option, **kwargs)
        return output

    @staticmethod
    def _environment_key(section, option):
        return (re.sub(r'\W+', '_', section) + '_' + re.sub(r'\W+', '_', option)).lower()

    @staticmethod
    def _decompress(data, algorithm):
        """
        Decompress a byte string based of the provided algorithm.
        :param data: byte string
        :param algorithm: string  with the name of the compression algorithm used
        :return: decompressed byte string.
        """
        if algorithm is None or algorithm == 'none':
            result = data
        elif algorithm == 'zlib':
            result = zlib.decompress(data)
        elif algorithm == 'bz2':
            result = bz2.decompress(data)
        else:
            raise ValueError("Compression {} is not supported.".format(algorithm))

        return result

    # TODO: Better error handling?
    def _get_ssm(self, name):
        """
        Gets a value from SSM parameter store
        Return None if name was not found, all other errors are raised.
        """
        self.logger.info('SSM GetParameter: "{0}"'.format(name))
        try:
            r = self.ssm.get_parameter(
                Name=name,
                WithDecryption=True)
        except ClientError as e:
            if e.response['Error']['Code'] == 'ParameterNotFound':
                return None
            else:
                raise
        return r['Parameter']['Value'].encode('utf8')

    def _get_ssm_ts(self, name):
        """
        Gets the value and last modified timestamp for the given parameter
        Return None if name was not found, all other errors are raised.
        Assume there is only one version stored
        """
        self.logger.info('SSM GetParameter with timestamp: "{0}"'.format(name))
        try:
            r = self.ssm.get_parameter_history(
                Name=name,
                WithDecryption=True)
        except ClientError as e:
            if e.response['Error']['Code'] == 'ParameterNotFound':
                return None
            else:
                raise
        return r['Parameters'][0]['Value'].encode('utf8'), r['Parameters'][0]['LastModifiedDate']

    def _get_keys(self, path=None):
        """
        Get all the ssm parameters below a given path and add last modified timestamps
        """
        if path is None:
            path = self.ca_key_prefix
        self.logger.info('SSM GetParametersByPath: With timestamps for path: "{0}"'.format(path))
        try:
            r = self.ssm.get_parameters_by_path(
                Path=path,
                Recursive=True,
                WithDecryption=True)
        except ClientError as e:
            if e.response['Error']['Code'] == 'ParameterNotFound':
                return None
            else:
                raise
        current_idx = None
        for i, param in enumerate(r['Parameters']):
            param['ts'] = self._get_ssm_ts(param['Name'])[1]
            if param['Name'] == '{}/current'.format(self.ca_key_prefix):
                current_idx = i
        return r['Parameters'], current_idx

    # TODO: Do we need better error handling?
    def _put_ssm(self, name, value, keyid, overwrite=False):
        """
        Put a value in SSM parameter store, using a provided KMS encryption key
        for secure storage.
        """
        self.logger.info('SSM PutParameter "{0}"'.format(name))
        self.ssm.put_parameter(
            Name=name,
            Value=value,
            Type='SecureString',
            KeyId=keyid,
            Overwrite=overwrite)

    def _del_ssm(self, name):
        """
        Remove parameter from SSM.
        """
        self.logger.info('SSM DeleteParameter "{0}"'.format(name))
        self.ssm.delete_parameter(Name=name)

    def _get_params(self, id):
        """
        Get the key with the given id from the cached structure (self.keys) retrieved from SSM
        /prefix/key.id
        /prefix/key.pub.id
        /prefix/passphrase.b64.id
        """
        # The structure is not very good for retrieving individual parameters, need to look at them all
        key_priv = None
        key_pub = None
        key_ts = None
        key_pass = None
        for param in self.keys:
            if param['Name'] == '{}/key.{}'.format(self.ca_key_prefix, id):
                key_priv = param['Value']
                key_ts = param['ts']
            elif param['Name'] == '{}/key.pub.{}'.format(self.ca_key_prefix, id):
                key_pub = param['Value']
            elif param['Name'] == '{}/passphrase.b64.{}'.format(self.ca_key_prefix, id):
                key_pass = param['Value']
        key = {'private': key_priv, 'public': key_pub, 'pass': key_pass, 'ts': key_ts}
        return key

    def _key_ok(self, key_ts=None):
        """
        Return True if key is stil valid and False if not
        """
        if key_ts is None:
            if hasattr(self, 'key_ts') and hasattr(self, 'key_priv') and self.key_ts is not None and self.key_priv is not None:
                key_ts = self.key_ts
            else:
                return False
        # Keys are used for one week, but created one week prior to first use. So validity * 2
        # But initial creation of keys might happen one week earlier than normal rotation, so even one more week: validity * 3.
        if key_ts + timedelta(seconds=(self.ca_key_validity * 3)) > datetime.now(pytz.utc):
            self.logger.info("_key_ok({}) True: Validity={} Now={} Future={}".format(key_ts, self.ca_key_validity, datetime.now(pytz.utc), key_ts + timedelta(seconds=(self.ca_key_validity * 3))))
            return True
        else:
            self.logger.info("_key_ok({}) True: Validity={} Now={} Future={}".format(key_ts, self.ca_key_validity, datetime.now(pytz.utc), key_ts + timedelta(seconds=(self.ca_key_validity * 3))))
            return False

    def _get_CA(self):
        """
        Read the CA from SSM, if it's not found, create a new one
        SSM Parameter path structure:
        /<prefix>/<instance>/private/<keyname>.<id>     - The private key
        /<prefix>/<instance>/private/<passphrase.<id>   - The passphrase of the private key
        /<prefix>/<instance>/public/current             - ID of active key
        /<prefix>/<instance>/public/<keyname>.<id>.pub  - The public key

        Example:
        /Bless/prod/private/bless-key.1
        /Bless/prod/private/bless-key.2
        /Bless/prod/private/passphrase.1
        /Bless/prod/private/passphrase.2
        /Bless/prod/public/current
        /Bless/prod/public/bless-key.1.pub
        /Bless/prod/public/bless-key.2.pub
        """

        (self.keys, self.current_idx) = self._get_keys()

        if self.keys is not None and len(self.keys) > 1:
            if self.current_idx is not None:
                self.id = int(self.keys[self.current_idx]['Value'])
                key = self._get_params(self.id)
                if self._key_ok(key['ts']):
                    self._set_key_cache(key)
                    return True
                else:
                    # TODO: Raise error?
                    self.logger.error('The current key (id: {}) is to old: {}'.format(self.id, key['ts']))
                    return False
            else:
                # TODO: Raise error?
                self.logger.error('No current pointer i SSM parameter store. Giving up!')
                return False
        else:
            # Create new keys from scratch
            self.logger.info('No keys found in SSM, so creating with ID 1 and 2.')
            key = self._create_CA(1)
            self._set_current(1)
            self._set_key_cache(key)
            self._create_CA(2)
            (self.keys, self.current_idx) = self._get_keys()
            return True

    def _set_current(self, id):
        """
        Set the current pointer in ssm to id and maintain self.id
        """
        self._put_ssm('{}/current'.format(self.ca_key_prefix), str(id), self.ca_private_key_key_id, True)
        self.id = id

    def _cache(self):
        """
        Make sure the cache is filled
        """
        if self._key_ok():
            return
        # Re-read from SSM
        self.logger.info("Cache is not warm, fill up using _get_CA()")
        self._get_CA()

    def _put_key(self, key, id):
        self._put_ssm("{}/key.{}".format(self.ca_key_prefix, id), key['private'], self.ca_private_key_key_id)
        self._put_ssm("{}/key.pub.{}".format(self.ca_key_prefix, id), key['public'], self.ca_public_key_key_id)
        self._put_ssm("{}/passphrase.b64.{}".format(self.ca_key_prefix, id), key['pass'], self.ca_passphrase_key_id)

    def _del_key(self, id):
        self._del_ssm("{}/key.{}".format(self.ca_key_prefix, id))
        self._del_ssm("{}/key.pub.{}".format(self.ca_key_prefix, id))
        self._del_ssm("{}/passphrase.b64.{}".format(self.ca_key_prefix, id))

    def _set_key_cache(self, key):
        """
        The key contains a dict with all key information, this function makes sure
        the rest of Bless after this will use the given key to serve clients
        """
        self.key_priv = key['private']
        self.key_pub = key['public']
        self.key_ts = key['ts']
        self.encrypted_password = key['pass']

    def _create_CA(self, id):
        """
        Create one CA, including private and public parts and passphrase
        Uses the configuration stored by __init__ in self.
        """
        passphrase = os.urandom(30).encode('base64').strip()
        try:
            stuff = self.kms.encrypt(KeyId=self.ca_passphrase_key_id,
                                Plaintext=passphrase)
            binary_encrypted = stuff[u'CiphertextBlob']
            encrypted_password = base64.b64encode(binary_encrypted)
        except ClientError as e:
            raise str(e)
        (key_priv, key_pub) = self._create_CA_key(self.ca_key_size, passphrase)
        key = {'private': key_priv, 'public': key_pub, 'pass': encrypted_password, 'ts': datetime.now(pytz.utc)}
        self._put_key(key, id)
        return key

    # https://stackoverflow.com/questions/2466401/how-to-generate-ssh-key-pairs-with-python/39126754#39126754
    # https://www.pythonsheets.com/notes/python-crypto.html#generate-rsa-keyfile-without-passphrase
    # TODO: Seed the cryptography module with randomness from KMS?
    #       Or maybe just use the exising code in bless_lambda.py to seed the entropy pool?
    #       Think maybe that bless_lambda.py seeds the OS random generator from KMS as needed?
    # TODO: Define a valid untill date for the created CA, and store that togehter with the CA in SSM
    #       Is that needed? As long as rotation is automatic, the key does not include a validity, so no need?
    @staticmethod
    def _create_CA_key(size, passphrase):
        """
        Create a new CA of given size and with given passphrase
        """
        key = rsa.generate_private_key(
            backend=crypto_default_backend(),
            public_exponent=65537,
            key_size=size
        )
        private_key = key.private_bytes(
            encoding=crypto_serialization.Encoding.PEM,
            format=crypto_serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=crypto_serialization.BestAvailableEncryption(passphrase)
        )
        public_key = key.public_key().public_bytes(
            crypto_serialization.Encoding.OpenSSH,
            crypto_serialization.PublicFormat.OpenSSH
        )

        # Get the ssh format public key
        ssh_public = public_key.decode('utf-8')
        return private_key, ssh_public

    # TODO: Maybe rotation should not delete the current key, but the previous current key?
    #       During rotation, when the key has been deleted from the host, users might still have
    #       active sessions running using the current key, that the servers no longer trusts?
    #       Or just let the servers keep the old certificate for a bit longer?
    def rotateCA(self):
        """
        Delete current key, add new and increase current counter.
        The caller need to verify that the caller is allowed to rotate the key
        """

        self.logger.info('ROTATE: Rotating CA.')

        if hasattr(self, 'id') or self.id is None:
            self._cache()
            if not hasattr(self, 'id') or self.id is None:
                self.logger.error('ROTATE: No current key, noting to rotate.')
                # Nothing to rotate! Just return.
                return

        # Process
        # 1. Create the new key
        # 2. Delete the old key
        # 3. Get the next active key from SSM
        # 4. Increase the current counter in SSM, so it points to the already created next key
        # 5. Update local key cache

        # Usually self.id contains current id
        # But during rotation self.id will change and we loose track of what was the current id.
        current_id = self.id
        self.logger.info('ROTATE: [0] Current ID: {}.'.format(current_id))

        # 1. Create next key
        next_id = current_id + 2
        self.logger.info('ROTATE: [1] Create key with ID: {}.'.format(next_id))
        key = self._create_CA(next_id)

        # 2. Delete current ID :
        self.logger.info('ROTATE: [2] Delete key with ID: {}.'.format(current_id))
        self._del_key(current_id)

        # 3. Get the new current key:
        self.logger.info('ROTATE: [3] Get next key from SSM with ID: {}.'.format(current_id + 1))
        (self.keys, self.current_idx) = self._get_keys()
        key = self._get_params(current_id + 1)

        # 4. Next current ID is id +1
        self.logger.info('ROTATE: [4] Next current key ID: {}.'.format(current_id + 1))
        self._set_current(current_id + 1)   # This will set self.id

        # 5. Update the local cache on what is the active key
        self.logger.info('ROTATE: [5] Update key cache (ts: {}). Old value: {}, new value: {}.'.format(key['ts'].ctime(), self.key_pub, key['public']))
        self._set_key_cache(key)
