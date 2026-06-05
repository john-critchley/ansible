#!/usr/bin/env python3
"""Create and attach a new EBS volume for /home, print the volume ID on success."""
import argparse, boto3, sys, time

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--instance-id', required=True)
    p.add_argument('--az', required=True)
    p.add_argument('--region', required=True)
    p.add_argument('--size', type=int, default=4)
    p.add_argument('--type', default='gp3', dest='vol_type')
    p.add_argument('--host', required=True)
    args = p.parse_args()

    ec2 = boto3.client('ec2', region_name=args.region)

    vol = ec2.create_volume(
        AvailabilityZone=args.az,
        Size=args.size,
        VolumeType=args.vol_type,
        TagSpecifications=[{'ResourceType': 'volume', 'Tags': [
            {'Key': 'Name',  'Value': f'{args.host}-home'},
            {'Key': 'Host',  'Value': args.host},
        ]}],
    )
    vol_id = vol['VolumeId']

    for _ in range(30):
        state = ec2.describe_volumes(VolumeIds=[vol_id])['Volumes'][0]['State']
        if state == 'available':
            break
        time.sleep(2)
    else:
        print(f'ERROR: volume {vol_id} never became available', file=sys.stderr)
        sys.exit(1)

    ec2.attach_volume(VolumeId=vol_id, InstanceId=args.instance_id, Device='/dev/sdf')

    for _ in range(30):
        state = ec2.describe_volumes(VolumeIds=[vol_id])['Volumes'][0]['State']
        if state == 'in-use':
            break
        time.sleep(2)
    else:
        print(f'ERROR: volume {vol_id} never attached', file=sys.stderr)
        sys.exit(1)

    print(vol_id)

if __name__ == '__main__':
    main()
