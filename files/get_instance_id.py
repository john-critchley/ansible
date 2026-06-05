#!/usr/bin/env python3
"""Usage: get_instance_id.py <public-ip> <region>"""
import sys
import boto3

ip, region = sys.argv[1], sys.argv[2]
ec2 = boto3.client('ec2', region_name=region)
r = ec2.describe_instances(Filters=[{'Name': 'ip-address', 'Values': [ip]}])
print(r['Reservations'][0]['Instances'][0]['InstanceId'])
