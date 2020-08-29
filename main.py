#!/usr/bin/env python3

"""awspfx

Usage:
    awspfx.py <profile>
    awspfx.py [(-c | --current) | (-l | --list) | (-s | --swap)]
    awspfx.py token [(-p | --profile) <profile>]
    awspfx.py sso [<login> | <token>]
    awspfx.py -h | --help
    awspfx.py --version

Examples:
    awspfx.py default # Change profile to 'default'
    awspfx.py token # Token from current profile
    awspfx.py token -p default # Token from profile 'default'
    awspfx.py (-c | -ls | -s)

Options:
    -h --help     Show this screen.
    --version     Show version.
    -p --profile  Select profile
    -t --token    Generate credentials
    -c --current  Change the profile
    -l --list    List profiles
    -s --swap     Swap previous the profile
"""

import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from configparser import ConfigParser as cfgParser

import boto3
from colorlog import ColoredFormatter
from docopt import docopt
from iterfzf import iterfzf


def setup_logging():
    LOG_LEVEL = logging.INFO
    LOGFORMAT = "\n%(log_color)s%(levelname)s%(reset)s => %(log_color)s%(message)s%(reset)s"
    logging.root.setLevel(LOG_LEVEL)
    formatter = ColoredFormatter(LOGFORMAT)
    stream = logging.StreamHandler()
    stream.setLevel(LOG_LEVEL)
    stream.setFormatter(formatter)
    log = logging.getLogger('pythonConfig')
    log.setLevel(LOG_LEVEL)
    log.addHandler(stream)

    return log


def exit_err(msg):
    log.error(msg)
    sys.exit()


def has_which(command, err=True):
    cmd = shutil.which(command) is not None
    if cmd:
        return command
    else:
        if err:
            exit_err(f"Command not installed: {command}")
        else:
            return False


def has_file(file, create=False):
    if os.path.isfile(file):
        return file
    else:
        if create:
            f = open(file, "w+")
            f.close()
        else:
            exit_err(f"File not exist: {file}")


def run_cmd(command):
    rc, out = subprocess.getstatusoutput(command)
    if rc != 0:
        err = "Occurred: ", out
        exit_err(err)
    return out


def fzf(data: list, current: str = None):
    cmd = has_which("fzf", err=False)

    if not cmd:
        print(*data, sep="\n")
        exit_err("Not installed 'fzf'")

    return iterfzf(data) or exit_err("you did not choose any of the options")


def sed_inplace(filename, pattern, repl):
    p = re.compile(pattern, re.MULTILINE)

    with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp_file:
        with open(filename, "r") as file:
            text = file.read()
            if "AWS_PROFILE" in text:
                new = p.sub(repl, text)
                tmp_file.write(new)
            else:
                print("No existe profile")
                tmp_file.write(text)
                tmp_file.write(f"export {repl}")

    shutil.copystat(filename, tmp_file.name)
    shutil.move(tmp_file.name, filename)


def current_profile(err=True):
    ctx = os.getenv("AWS_PROFILE")
    if err:
        return ctx or exit_err("Getting current profile")
    return ctx


def get_profiles(err=True):
    cmd = f"unset AWS_PROFILE; {AWS} configure list-profiles | sort -n"
    resp = run_cmd(cmd)
    ctx = list(resp.split("\n")) if resp else None
    if err:
        return ctx or exit_err("Getting profile list")
    return ctx


def list_profiles(lst=False):
    ctx_current = current_profile(err=False)
    ctx_list = get_profiles()
    if lst:
        print(*ctx_list, sep="\n")
    else:
        p = fzf(data=ctx_list, current=ctx_current)
        return p


def read_profile():
    with open(AWSPFX_CACHE, 'r') as file:
        r = file.read()
        return r


def save_profile(ctx_current):
    ctx = ctx_current if ctx_current else ""
    with open(AWSPFX_CACHE, "w") as file:
        file.write(ctx)


def switch_profile(ctx, ctx_current):
    ctx_old = f'AWS_PROFILE="{ctx_current}"'
    ctx_repl = f'AWS_PROFILE="{ctx}"'

    sed_inplace(ENVRC_FILE, ctx_old, ctx_repl)
    save_profile(ctx_current)

    run_cmd("direnv allow && direnv reload")


def set_profile(ctx, ctx_current=None, sms=None):
    if not ctx_current:
        ctx_current = current_profile(err=False)

    if ctx == ctx_current:
        log.warning(f"The profile is not changed: {ctx_current}")
    else:
        switch_profile(ctx, ctx_current)
        sms_text = sms if sms else f"Switched to profile: {ctx}"
        log.info(sms_text)


def swap_profile():
    ctx = read_profile()
    if ctx:
        sms_text = f"Switched to previous profile: {ctx}"
        set_profile(ctx=ctx, sms=sms_text)


def exist_profile(ctx):
    if ctx in get_profiles():
        return True
    else:
        exit_err(f"Profile does not exist: {ctx}")


def get_token(ctx):
    aws_cred = cfgParser()
    aws_cred.read(CREDS_FILE)

    act_id = os.getenv('AWS_ACCOUNT_ID') or aws_cred.get(ctx, 'account_id')
    act_role = os.getenv('AWS_ROLE_NAME') or aws_cred.get(ctx, 'role_name')
    act_region = os.getenv('AWS_REGION') or aws_cred.get(ctx, 'region')

    aws_sso_cache = os.path.expanduser('~/.aws/sso/cache')

    json_files = [
        pos_json for pos_json in os.listdir(
            aws_sso_cache
        ) if pos_json.endswith(
            '.json'
        )
    ]

    for json_file in json_files:
        path = f"{aws_sso_cache}/{json_file}"
        with open(path) as file:
            data = json.load(file)
            if 'accessToken' in data:
                accessToken = data['accessToken']

    client = boto3.client('sso', region_name='us-east-1')

    res = client.get_role_credentials(
        accountId=act_id,
        roleName=act_role,
        accessToken=accessToken
    )

    aws_access_key_id = res['roleCredentials']['accessKeyId']
    aws_secret_access_key = res['roleCredentials']['secretAccessKey']
    aws_session_token = res['roleCredentials']['sessionToken']

    session = boto3.Session(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        aws_session_token=aws_session_token,
        region_name=act_region
    )

    # print('Save Credentials in ~/.aws/credentials ...')

    aws_cred.set(ctx, 'aws_access_key_id', aws_access_key_id)
    aws_cred.set(ctx, 'aws_secret_access_key', aws_secret_access_key)
    aws_cred.set(ctx, 'aws_session_token', aws_session_token)

    with open(CREDS_FILE, 'w') as f:
        aws_cred.write(f)


def main(argv):
    ctx = argv["<profile>"]

    if ctx == "token" or argv["token"]:
        if argv["--profile"]:
            if exist_profile(ctx):
                get_token(ctx)
                log.info(f"Generate token to: {ctx}")
        else:
            ctx = current_profile()
            get_token(ctx)
            log.info(f"Generate token to: {ctx}")

        sys.exit()

    if ctx == "sso" or argv["sso"]:
        print("sso")
        sys.exit()

    if argv["--current"]:
        log.info(f"The current profile is: '{current_profile()}'")
        sys.exit()

    if argv["--list"]:
        list_profiles(lst=True)
        sys.exit()

    if argv["--swap"]:
        swap_profile()
        sys.exit()

    if ctx or ctx is None:
        if ctx is None:
            ctx_profile = list_profiles()
        else:
            ctx_profile = ctx if exist_profile(ctx) else sys.exit()

        set_profile(ctx_profile)

        sys.exit()


if __name__ == "__main__":
    log = setup_logging()
    HOME = os.getenv('HOME') or exit_err("Home directory does not exist?")
    AWS = has_which("aws")
    AWSPFX_CACHE = has_file(f"{HOME}/.aws/awspfx", create=True)
    DIRENV = has_which("direnv")
    ENVRC_FILE = has_file(f"{HOME}/.envrc")
    CREDS_FILE = has_file(f"{os.getenv('HOME')}/.aws/credentials")

    arguments = docopt(__doc__, version='awspfx 0.1.0')
    main(arguments)
