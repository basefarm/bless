#!/usr/bin/python
import boto3, json, configparser, pwd, grp, subprocess, os, argparse, sys, shutil, random, time
from botocore.exceptions import ClientError

class BlessSync:
    """ Script to get public CA's and IAM groups from Bless based on configuration from SSM parameter store"""
    def __init__(self, config):
        self.config = config 

    def assume_role(self, roleArn):
        sts_client = boto3.client('sts')
        assumedRoleObject = sts_client.assume_role(
            RoleArn=roleArn,
            RoleSessionName="BlessAssumeRoleSession"
        )
        return assumedRoleObject['Credentials']
        
    def lambda_client(self, region, credentials=None):
        if credentials != None:
            client = boto3.client('lambda', region_name=region,
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
               aws_session_token=credentials['SessionToken'])
        else:
            client = boto3.client('lambda', region_name=region)
        return client

    def get_public_cas(self, lambda_client, functionName):
        ca_list = []
        response = lambda_client.invoke(FunctionName=functionName,
            InvocationType='RequestResponse', LogType='None',
            Payload=json.dumps({'get-public-cas': True})
        )

        if response['StatusCode'] != 200:
            print(response)
            raise ValueError('Return StatusCode is not 200')

        payload = json.loads(response['Payload'].read().decode())
        if 'public-cas' not in payload:
            print(payload)
            raise ValueError('Missing public-cas in payload')
        for ca in payload['public-cas']:
            ca_list.append(ca['key'])
        return ca_list

    def make_bless_ca_file(self, ca_list):
        try:
            old_diff = None
            new_diff = ''
            ca_file = self.config.get('bless','ca_file')
            sshd_config = self.config.get('bless','sshd_config')
            if os.path.exists(ca_file):
                fi = open(ca_file, 'r')
                old_diff = fi.read()
                fi.close()
            fi = open(ca_file,'w')
            for ca in ca_list:
                new_diff += ca + '\n'
                fi.write(ca + '\n')
            fi.close()
            line = 'TrustedUserCAKeys %s' % ca_file
            with open(sshd_config, 'a+') as f:
                if not any(line == x.rstrip('\r\n') for x in f):
                    f.write('\n'+line + '\n')
                    print('Added "%s" to %s' % (line, sshd_config))
            if new_diff != old_diff:
                exitcode = subprocess.call([config.get('bless','service_path'), 'sshd', 'reload'])
                if exitcode != 0:
                    print('Failed to reload sshd service')
        except Exception as err:
            raise

    def get_iam_users(self,lambda_client, functionName):
        response = lambda_client.invoke(FunctionName=functionName,
                    InvocationType='RequestResponse', LogType='None',
                    Payload=json.dumps({'get-users': True})
        )
        if response['StatusCode'] != 200:
            print(response)
            raise ValueError('Return StatusCode is not 200')
        payload = json.loads(response['Payload'].read().decode())
        if 'users' not in payload:
            print(payload)
            raise ValueError('Missing users in payload')
        return payload['users']

    def wait_for_mount(self, path, dirtype):
        """
        Will activly wait for the given path to be mounted with the given file system type
        """
        if dirtype == '':
            return True
        if path == '':
            return False
        res=''
        timeout=360
        t=0
        while res != dirtype and t < timeout:
            if os.path.isdir(path):
                res=subprocess.check_output([ 'df', '--output=fstype', path ])
                # Remove the first line/header
                res=res.split("\n")[1]
                print("Found fs type: %s for %s" % (res, path))
                if res == dirtype:
                    print("Waited %s seconds for %s to become fs of type %s" % (str(t), path, dirtype) )
                    return True
            time.sleep( 5 )
            t += 5

        if res != dirtype:
            return False
        else:
            return True


    def create_user(self, username):
        try:
            homedir = "%s/%s" % (self.config.get('bless','default_home'),username)
            if not os.path.isdir(self.config.get('bless','default_home')):
                os.makedirs(self.config.get('bless','default_home'), 0o755)
            if os.path.isdir(homedir):
                uid = os.stat(homedir).st_uid
                exitcode = subprocess.call(
                    [
                        self.config.get('bless','useradd_path'), "-s", self.config.get('bless','default_shell'),
                        "-c", "iamsync", "-mb", self.config.get('bless','default_home'), "--uid", str(uid), username
                        ]
                    )
            else:
                exitcode = subprocess.call(
                    [
                        self.config.get('bless','useradd_path'), "-s", self.config.get('bless','default_shell'),
                        "-c", "iamsync", "-mb", self.config.get('bless','default_home'),
                        "-K", "UID_MIN=%s" % self.config.get('bless', 'default_uid_min'),
                        "-K", "UID_MAX=%s" % self.config.get('bless', 'default_uid_max'), username
                        ]
                    )
            print("Creating user %s, exited with code %s" % (username, exitcode))
            return True
        except Exception as e:
            print(e)
            return False

    def create_group(self, groupname):
        try:
            exitcode = subprocess.call([self.config.get('bless','groupadd_path'), groupname])
            print("Creating group %s, exited with code %s" % (groupname, exitcode))
            #For now we just give the group sudo access
            line = '%%%s ALL = (ALL) NOPASSWD: ALL \n' % (groupname)
            tmp_file = '/tmp/sudoers.%s.tmp' % (groupname)
            new_file = '/etc/sudoers.d/%s' % (groupname)
            with open(tmp_file, 'w') as f:
                f.write(line)
                f.close()
            # Check that the file is valid
            exitcode = subprocess.call([self.config.get('bless', 'visudo_path'), "-cf", tmp_file])
            if exitcode != 0:
                print("Failed to add group to sudoers, test failed")
                return False
            shutil.copy(tmp_file, new_file)
            os.chmod(new_file, 0o440)
            return True
        except Exception as e:
            raise e

    def check_if_user_exists(self, username):  
        try:
            check = pwd.getpwnam(username)
            return True
        except KeyError:
            return False

    def check_if_group_exists(self, groupname):
        try:
            check = grp.getgrnam(groupname)
            return True
        except KeyError:
            return False

    def get_from_ssm(self, ssm, names):
        x = {}
        r = ssm.get_parameters(
            Names=names,
            WithDecryption=True)
        for parameter in r['Parameters']:
            x[parameter['Name']] = parameter['Value']
        return x

    def remove_defunct_users(self, users):  
        allusers = pwd.getpwall()
        defunct = []
        try:
            for u in allusers:
                delete = False
                # set delete to True if the user's comment is iamsync
                if pwd.getpwnam(u.pw_name).pw_gecos == "iamsync":
                    delete = True

                # Check each group's membership for the user
                # If any group has that user as a member, set delete to False
                if u.pw_name in users:
                    delete = False

               # If delete is True, add to list of defunct users
                if delete:
                    defunct.append(u.pw_name)
            if defunct:
                print("Defunct Users: {}".format(defunct))

            for u in defunct:
                exitcode = subprocess.call(
                [self.config.get('bless','userdel_path'), u]
                )
                print("Removing user {} exited with code {}".format(u, exitcode))
        except Exception as e:
            print(e)

    @staticmethod
    def get_random_seed():  
        try:
            res = subprocess.check_output(
                [
                    "uname", "-a"
                ]
            )
            return res
        except Exception as e:
            print(e)
            return "Not so good randomness"

    def create_cronjob(self, cron, user, config_file):
        cron_file = self.config.get('bless','cronfile')
        cmd = '%s %s/%s --config-file %s >> /var/log/bless.log 2>&1' % (sys.executable, os.path.dirname(os.path.realpath(__file__)),'bless-sync.py',config_file)
        header = 'PATH=/sbin:/bin:/usr/sbin:/usr/bin\n'
        # RANDOM_DELAY=59, not usable on ubuntu
        line = '%s %s %s\n' % (cron, user, cmd)
        with open(config.get('bless','cronfile'), 'w') as f:
            f.write(header)
            f.write(line)
            f.close()
    
    def remove_user_from_group(username, groupname):  
        try:
            subprocess.call(
                [
                    "gpasswd", "-d", username, groupname
                ]
            )
        except Exception as e:
            print(e)

    def add_user_to_group(self, username, groupname):  
        try:
            exitcode = subprocess.call(
                [
                    "usermod", "-aG", groupname, username
                ]
            )
            print("Adding user %s to group %s exited with code %s" % (username, groupname, exitcode))
        except Exception as e:
            print(e)

if __name__ == "__main__":
    for service in ['/sbin/service', '/usr/sbin/service']:
        if os.path.exists(service):
            service_path = service
    random.seed(BlessSync.get_random_seed())
    minute=random.randint(1,59)
    DEFAULT_CONFIG = {'bless':{
        'ca_file': '/etc/ssh/bless-ca.pub',
        'sshd_config': '/etc/ssh/sshd_config',
        'useradd_path': '/usr/sbin/useradd',
        'groupadd_path': '/usr/sbin/groupadd',
        'visudo_path': '/usr/sbin/visudo',
        'userdel_path': '/usr/sbin/userdel',
        'default_shell': '/bin/bash',
        'default_home': '/home',
        'default_home_type' : '',
        'default_uid_min': '1000',
        'default_uid_max': '1999',
        'default_cron': "{} * * * *".format(str(minute)),
        'cronfile': '/etc/cron.d/bless',
        'service_path': service_path
    }}
    config = configparser.ConfigParser()
    config.read_dict(DEFAULT_CONFIG)
    default_configfile = os.path.dirname(os.path.realpath(__file__))

    aparser = argparse.ArgumentParser(description='Bless-sync.py')
    aparser.add_argument('--instances', help='Comma Separated List of BLESS instances')
    aparser.add_argument('--regions', help='Comma Separated List of AWS regions')
    aparser.add_argument('--config-file', help='Config file. Default %s/config.ini' % (default_configfile), default='%s/config.ini' % (default_configfile))
    aparser.add_argument('--reinstall', help='This will reinstall crontab, force update of ca file and recreate config file', action="store_true")
    aparser.add_argument('--cron', help="What cron interval to run bless-sync in. Default '%s'" % (config.get('bless', 'default_cron')))
    aparser.add_argument('--base-dir', help="The home directory base. Default '%s'" % (config.get('bless', 'default_home')))
    aparser.add_argument('--base-dir-type', help="The home directory base dir type. Default ''")
    aparser.add_argument('--uid-min', help="The minimum UID for new users. Default '%s'" % (config.get('bless', 'default_uid_min')))
    aparser.add_argument('--uid-max', help="The maximum UID for new users. Default '%s'" % (config.get('bless', 'default_uid_max')))
    aparser.add_argument('--cron-user', help="What user cronjob is run under. Default root", default='root')
    args = vars(aparser.parse_args())
    
    if args['config_file'] is None:
        config_file = '%s/config.ini' % (os.path.dirname(os.path.realpath(__file__)))
    else:
        config_file = args['config_file']
    config.read(config_file)

    if args['instances'] is not None:
        instances = args['instances'].split(',')
        config['bless']['instances'] = args['instances']
    elif 'instances' in config['bless']:
        instances = config['bless']['instances'].split(',')
    else:
        print('Instances is a required field. Must be set by argument or in config file')
        sys.exit()

    if args['regions'] is not None:
        regions = args['regions'].split(',')
        config['bless']['regions'] = args['regions']
    elif 'regions' in config['bless']:
        regions = config['bless']['regions'].split(',')
    else:
        print('Regions is a required field. Must be set by argument or in config file')
        sys.exit()

    if args['base_dir'] is not None:
        config['bless']['default_home'] = args['base_dir']
    if args['base_dir_type'] is not None:
        config['bless']['default_home_type'] = args['base_dir_type']
    if args['uid_min'] is not None:
        config['bless']['default_uid_min'] = args['uid_min']
    if args['uid_max'] is not None:
        config['bless']['default_uid_max'] = args['uid_max']
    if args['cron'] is not None:
        config['bless']['default_cron'] = args['cron']

    blessSync = BlessSync(config)

    if args['reinstall'] or os.path.exists(config['bless']['cronfile']) is False:
        blessSync.create_cronjob(config['bless']['default_cron'], args['cron_user'], args['config_file'])
        print('Created cronfile %s' % (config['bless']['cronfile']))

    # Write the config file to disk if requested or do not exists
    if args['reinstall'] or os.path.exists(config_file) is False:
        with open(config_file, 'w') as configfile:
            config.write(configfile)

    ca_list = []


    for instance in instances:
        BlessRegions = None
        BlessFunction = None
        Role = None
        for region in regions:
            ssm_client = boto3.client('ssm', region_name=region)
            try:
                ssm_parameters = blessSync.get_from_ssm(ssm_client, ['/Bless/%s/BlessFunction' % instance, '/Bless/%s/Role' % instance, '/Bless/%s/Regions' % instance])
                BlessFunction = ssm_parameters['/Bless/%s/BlessFunction' % instance]
                Role = ssm_parameters['/Bless/%s/Role' % instance]
                br = ssm_parameters['/Bless/%s/Regions' % instance]
                BlessRegions = br.split(',')
                break
            except Exception as e:
                print("Failed to get parameters from instance '%s' in region '%s'.\nError: %s\n" % (instance, region, e))
                continue

        if BlessRegions is None or BlessFunction is None or Role is None:
            print("ERROR: Unable to get parameters for instance '%s' in regions '%s'" % (instance, ",".join(regions)))
            continue

        # Wait here for mount of basedir (/home)
        if not blessSync.wait_for_mount(config.get('bless','default_home'),config.get('bless','default_home_type')):
            print("ERROR: Unable for verify that %s is of type %s before we hit timeout." % (config.get('bless','default_home'),config.get('bless','default_home_type')))

        for region in BlessRegions:
            credentials = None
            credentials = blessSync.assume_role(Role)
            print("%s / %s" % (instance, region))
            client = blessSync.lambda_client(region, credentials)
            ca_list += blessSync.get_public_cas(client, BlessFunction)
            users = blessSync.get_iam_users(client, BlessFunction)
            if users is not None:
                for user in users:
                    if blessSync.check_if_user_exists(user) is False:
                        blessSync.create_user(user)
                    groups = [g.gr_name for g in grp.getgrall() if user in g.gr_mem]
                    for group in users[user]['groups']:
                        if blessSync.check_if_group_exists(group) is False:
                            blessSync.create_group(group)
                        if group not in groups:
                            blessSync.add_user_to_group(user, group)
                blessSync.remove_defunct_users(users)

    if len(ca_list) > 0:
        blessSync.make_bless_ca_file(ca_list)
