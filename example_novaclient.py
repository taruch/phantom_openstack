#!/usr/bin/env python

import os, sys, time

from novaclient.client import Client as nv_client
from cinderclient.client import Client as cn_client
from novaclient import auth_plugin as nv_auth_plugin
from novaclient import utils
from argparse import Namespace

NOVA_VERSION = '1.1'
CINDER_VERSION = '1'

os_cert = utils.env('OS_CERT') or env_error('OS_CERT')
os_key = utils.env('OS_KEY') or env_error('OS_KEY')
os_cacert = utils.env('OS_CACERT') or env_error('OS_CACERT')
os_username = utils.env('OS_USERNAME') or env_error('OS_USERNAME')
os_tenant_name = utils.env('OS_TENANT_NAME') or env_error('OS_TENANT_NAME')
os_region_name = utils.env('OS_REGION_NAME') or env_error('OS_REGION_NAME')
os_auth_url = utils.env('OS_AUTH_URL') or env_error('OS_AUTH_URL')
os_auth_system = utils.env('OS_AUTH_SYSTEM') or env_error('OS_AUTH_SYSTEM')

# ok if this not set
os_password = utils.env('OS_PASSWORD')

nv_auth_plugin.discover_auth_systems()
auth_plugin = nv_auth_plugin.load_plugin(os_auth_system)

authz_args = Namespace(os_password=os_password, os_cacert=os_cacert, os_cert=os_cert, os_key=os_key)
auth_plugin.parse_opts(authz_args)

nova = nv_client(NOVA_VERSION, os_username, os_password, os_tenant_name, auth_url=os_auth_url, region_name=os_region_name,
                            cacert=os_cacert, auth_system=os_auth_system, auth_plugin=auth_plugin)

cinder = cn_client(CINDER_VERSION, os_username, os_password, os_tenant_name, auth_url=os_auth_url, region_name=os_region_name,
                            cacert=os_cacert, auth_system=os_auth_system, auth_plugin=auth_plugin)

#get current instances
instances = nova.servers.list()

#get current volumes
volumes = cinder.volumes.list()

#get current keys
keys = nova.keypairs.list()

deployed_instances = []
for instance in instances:
    deployed_instances.append(instance.name)

print deployed_instances

for keyno in xrange(len(keys)):
    print "{0}: {1}".format( keyno, keys[keyno].name )

userinput = raw_input("Please pick a key to use:  ")
mykey = keys[int(userinput)].name

createinstances = open("./create_instances.txt", 'r').read().split('\n')

cindersize = 0
cinderdisplay_name = ""

for inst in createinstances:
    if inst:
        instparsed = inst.split(',')
        inst_name = instparsed[0]
        cinderdisplay_name = "None"
        if inst_name in deployed_instances:
            print "Instance {0} already deployed - NEXT!!".format(inst_name)
            continue
        else:
            print "Creating {0}".format(inst_name)
            inst_flavor = instparsed[1]
            inst_image = instparsed[2]
            cindersize = int(instparsed[3])
            if len(instparsed) > 4:
                cinderdisplay_name = instparsed[4]


            #get flavor object
            flavor = nova.flavors.find(name=inst_flavor)

            #get image object
            image = nova.images.find(name="CentOS 6.latest")

            instance = nova.servers.create(name=inst_name, image=image, flavor=flavor, key_name=mykey)

            instStatus = 'BUILD'
            iteration_cnt = 0
            while instStatus != 'ACTIVE':
                time.sleep(10)
                # Retrieve the instance again so the status field updates
                instance = nova.servers.get(instance.id)
                instStatus = instance.status
                print "Build State: {0}".format(instStatus)
                iteration_cnt += 1
                if iteration_cnt == 12:
                    print "Instance {0} didn't build - killing and starting over".format(inst_name)
                    instance.delete()
                    break




            if cindersize is not 0:
                volume = cinder.volumes.create(cindersize, display_name=cinderdisplay_name)
                resp = cinder.volumes.attach(volume.id, instance.id, '/dev/vdb', mode='rw')
                print resp

            
            floating_ip = ''
            for nic_ip in instance.addresses.values()[0]:
                if nic_ip.get('OS-EXT-IPS:type') == "fixed":
                    continue
                if nic_ip.get('OS-EXT-IPS:type') == "floating":
                    floating_ip = nic_ip.get('addr')

            if floating_ip == '':
                floating_ip_list = nova.floating_ips.list()
                for ip in floating_ip_list:
                    if ip.instance_id == None:
                        floating_ip = ip
                        break
                if floating_ip == '':
                    floating_ip = nova.floating_ips.create()


                resp = instanc
