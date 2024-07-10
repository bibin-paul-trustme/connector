import subprocess
import configparser 
import xml.etree.ElementTree as ET
import os

config = configparser.ConfigParser()
config.read("svn_config.ini")

svn_path = config['LOCAL']['SVN_PATH']
def branch_list(account):
    
    if account.endswith('/'):
        account = account[:-1]
    
    base_url =  account+'/branches'
    branch_cmd = [svn_path, 'list', '--no-auth-cache', '--trust-server-cert', '--non-interactive', '--xml', base_url.strip()]
    branch_resp = subprocess.run(branch_cmd, capture_output=True, text=True)
    if branch_resp.returncode == 0:
        root = ET.fromstring(branch_resp.stdout)
        list_element = root.find('list')
        branches = [entry.find('name').text for entry in list_element.findall('entry')]
    else:
        branches = []
    branch_list = ['branches/'  + s for s in branches]
    base_url =  account+'/tags'
    tag_cmd = [svn_path, 'list',  '--no-auth-cache', '--trust-server-cert', '--non-interactive','--xml', base_url.strip()]
    tag_resp = subprocess.run(tag_cmd, capture_output=True, text=True)
    if tag_resp.returncode == 0:
        root = ET.fromstring(tag_resp.stdout)
        list_element = root.find('list')
        tags = [entry.find('name').text for entry in list_element.findall('entry')]
    else:
        tags = []
    tag_list = ['tags/'  + s for s in tags]
    branches = branch_list + tag_list
    base_url =account+'/trunk'
    trunk_cmd = [svn_path, 'info',  '--no-auth-cache', '--trust-server-cert', '--non-interactive','--xml', base_url.strip()]
    trunk_resp = subprocess.run(trunk_cmd, capture_output=True, text=True)
    if trunk_resp.returncode == 0:
        branches = branches + ['trunk']
    return branches

def repo_update(url):
    print('============Repo Update======================')
    print(url)
    if url.endswith('/'):
        folder_name = url.split('/')[-2]
        url = url.split('/')[-1]
    else:
        folder_name = url.split('/')[-1]
    print(os.path.exists(folder_name) and os.path.isdir(folder_name))
    if os.path.exists(folder_name) and os.path.isdir(folder_name):
        svn_cmd = [svn_path,  '--no-auth-cache', '--trust-server-cert', '--non-interactive', 'update', folder_name]
        response_repo = subprocess.run(svn_cmd, capture_output=True, text=True)
    else:

        svn_cmd = [svn_path,  '--no-auth-cache', '--trust-server-cert', '--non-interactive', 'checkout', url]
        print(svn_cmd)
        response_repo = subprocess.run(svn_cmd, capture_output=True, text=True)
        print(response_repo)
    return response_repo 