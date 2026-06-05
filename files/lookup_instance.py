#!/usr/bin/env python3
"""Usage: lookup_instance.py <name-tag> <region>  — prints: instance_id az"""
import sys, boto3

name, region = sys.argv[1], sys.argv[2]
ec2 = boto3.client('ec2', region_name=region)
r = ec2.describe_instances(Filters=[
    {'Name': 'tag:Name', 'Values': [name]},
    {'Name': 'instance-state-name', 'Values': ['running']},
])
inst = r['Reservations'][0]['Instances'][0]
print(inst['InstanceId'], inst['Placement']['AvailabilityZone'])
