#!/usr/bin/env python3

"""awspfx

Usage:
    awspfx.py <profile>
    awspfx.py [(-c | --current) | (-l | --list) | (-s | --swap)]
    awspfx.py token [(-p | --profile) <profile>]
    awspfx.py sso [(login | token)] [(-p | --profile) <profile>]
    awspfx.py -h | --help
    awspfx.py --version

Examples:
    awspfx.py default               # Change profile to 'default'
    awspfx.py token                 # Token from current profile, default from SSO
    awspfx.py token -p default      # Token from profile 'default'
    awspfx.py (-c | -l | -s)

SubCommands:
    token         Generate credentials
    -p --profile  Select profile

Options:
    -c --current  Change the profile
    -l --list     List profiles
    -s --swap     Swap previous the profile
    -h --help     Show this screen.
    --version     Show version.

WIP:
    sso           Option to login
    sts           Option to assume-role
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
    log_level = logging.INFO
    log_format = "\n%(log_color)s%(levelname)s%(reset)s => %(log_color)s%(message)s%(reset)s"
    logging.root.setLevel(log_level)
    formatter = ColoredFormatter(log_format)
    stream_ = logging.StreamHandler()
    stream_.setLevel(log_level)
    stream_.setFormatter(formatter)
    log_ = logging.getLogger("pythonConfig")
    log_.setLevel(log_level)
    log_.addHandler(stream_)

    return log_


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
    f = os.path.isfile(file) or False

    if not f:
        if create:
            f_ = open(file, "w+")
            f_.close()
        else:
            exit_err(f"File not exist: {file}")

    return file


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

    with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp_file:
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


def setup_aws(ctx: str = None):
    try:
        if ctx is None:
            # if aws_profile_env is None:
            #     del os.environ['AWS_PROFILE']
            aws_session = boto3.session.Session()
        else:
            aws_session = boto3.session.Session(profile_name=ctx)

        return aws_session
    except Exception as e:
        exit_err(e)


def current_profile(err=True):
    ctx = aws.profile_name
    if err:
        return ctx or exit_err("Getting current profile")
    return ctx


def get_profiles(err=True):
    try:
        ctx_ls = aws.available_profiles
        ctx = sorted(ctx_ls, reverse=True)
        if err:
            return ctx or exit_err("Getting profile list")
        return ctx
    except Exception as e:
        log.error(e)


def list_profiles(lst=False):
    ctx_current = current_profile(err=False)
    ctx_list = get_profiles()
    if lst:
        ctx = reversed(ctx_list)
        print(*ctx, sep="\n")
    else:
        p = fzf(data=ctx_list, current=ctx_current)
        return p


def read_profile():
    with open(awspfx_cache, 'r') as file:
        r = file.read()
        return r


def save_profile(ctx_current):
    ctx = ctx_current if ctx_current else ""
    with open(awspfx_cache, "w") as file:
        file.write(ctx)


def switch_profile(ctx, ctx_current):
    ctx_old = f"AWS_PROFILE={ctx_current}"
    ctx_repl = f"AWS_PROFILE={ctx}"

    sed_inplace(envrc_file, ctx_old, ctx_repl)
    save_profile(ctx_current)

    run_cmd("direnv allow && direnv reload")


def set_profile(ctx, ctx_current=None, sms=None):
    if not ctx_current:
        ctx_current = current_profile(err=False)

    if ctx == ctx_current:
        log.warning(f"The profile is not changed: {ctx_current}")
    else:
        switch_profile(ctx, ctx_current)
        sms_text = sms or f"Switched to profile: {ctx}"
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


def sso(account_id, role_name):
    client = aws.client("sso", region_name="us-east-1")

    aws_sso_cache = os.path.expanduser("~/.aws/sso/cache")

    json_files = [
        pos_json for pos_json in os.listdir(
            aws_sso_cache
        ) if pos_json.endswith(
            ".json"
        )
    ]

    for json_file in json_files:
        path = f"{aws_sso_cache}/{json_file}"
        with open(path) as file:
            data = json.load(file)
            if "accessToken" in data:
                access_token = data['accessToken']

    try:
        cred = client.get_role_credentials(
            accountId=account_id,
            roleName=role_name,
            accessToken=access_token
        )

        return cred
    except Exception as e:
        log.error(e)
        log.warning("The SSO session associated with this profile has expired "
                    "or is otherwise invalid. To refresh this SSO session run "
                    "aws sso login with the corresponding profile.")
        sys.exit(2)


def sts(account_id, role, region):
    role_info = {
        "RoleArn": f"arn:aws:iam::{account_id}:role/{role}",
        "RoleSessionName": "session01"
    }

    client = aws.client("sts", region_name=region)
    cred = client.assume_role(**role_info)

    return cred


def get_token(ctx, sso_=True, sts_=False):
    aws_cred = cfgParser()
    aws_cred.read(creds_file)

    act_id = os.getenv("AWS_ACCOUNT_ID") or aws_cred.get(ctx, "account_id")
    act_role = os.getenv("AWS_ROLE_NAME") or aws_cred.get(ctx, "role_name")
    act_region = os.getenv("AWS_REGION") or aws_cred.get(ctx, "region")

    if sso_:
        cred = sso(account_id=act_id, role_name=act_role)
    elif sts_:
        cred = sts(account_id=act_id, role=act_role, region=act_region)
    else:
        cred = {}
        exit_err("Not select option from token")

    aws_access_key_id = cred['roleCredentials']['accessKeyId']
    aws_secret_access_key = cred['roleCredentials']['secretAccessKey']
    aws_session_token = cred['roleCredentials']['sessionToken']

    # print('Save Credentials in ~/.aws/credentials ...')
    aws_cred.set(ctx, "aws_access_key_id", aws_access_key_id)
    aws_cred.set(ctx, "aws_secret_access_key", aws_secret_access_key)
    aws_cred.set(ctx, "aws_session_token", aws_session_token)

    with open(creds_file, "w") as f:
        aws_cred.write(f)


def main(argv):
    ctx = argv['<profile>']

    if ctx == "token" or argv['token']:
        if argv['--profile']:
            if exist_profile(ctx):
                get_token(ctx)
                log.info(f"Generate token to: {ctx}")
        else:
            ctx = current_profile()
            get_token(ctx)
            log.info(f"Generate token to: {ctx}")

        sys.exit()

    if ctx == "sso" or argv['sso']:
        print("sso")
        sys.exit()

    if argv['--current']:
        log.info(f"The current profile is: '{current_profile()}'")
        sys.exit()

    if argv['--list']:
        list_profiles(lst=True)
        sys.exit()

    if argv['--swap']:
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
    home_path = os.getenv('HOME') or exit_err("Home directory does not exist?")
    # aws_profile_env = os.getenv("AWS_PROFILE")
    aws = setup_aws()
    awspfx_cache = has_file(f"{home_path}/.aws/awspfx", create=True)
    direnv = has_which("direnv")
    envrc_file = has_file(f"{home_path}/.envrc")
    creds_file = has_file(f"{home_path}/.aws/credentials")

    arguments = docopt(__doc__, version='awspfx 0.1.5')
    main(arguments)
