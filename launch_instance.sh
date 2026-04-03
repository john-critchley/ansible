#!/usr/bin/bash
instance_name=thursday
region=eu-central-1
instance_type=t3.medium
ami=ami-00ebb2b898eebe380
spot=no
while let $#\>0
do
case "$1" in
 --instance-name) # name which will be used as Name in AWS and in hosts file
  instance_name=$2
  shift
  ;;
 --region) # AWS region to launch in
  region=$2
  shift
  ;;
 --instance-type) # size and architecture of host requestes
  instance_type=$2
  shift
  ;;
 --ami) # what initial image to use to build machine
  ami=$2
  shift
  ;;
 --spot) # Include to get a spot instance
  spot=yes
  shift
  ;;
 *)
  sed -ne '/\*)/q;s/) #/\n  /p' $0
  echo "$1" not understood
  echo Example:
  echo $0 --instance-name thursday --region eu-central-1 --instance-type t3.medium --ami ami-00ebb2b898eebe380 --spot yes
  exit 1
  ;;
 esac 
 shift
done
s="$0 --instance-name $instance_name --region $region --instance-type $instance_type --ami $ami"
[ yes = "$spot" ] && s="$s --spot"
echo -e $s >> $HOME/aws/.start.log

#echo ansible-playbook launch_instance.yml -e "instance_name=thursday region=eu-central-1 instance_type=t3.medium ami=ami-00ebb2b898eebe380 spot=yes"
ansible-playbook launch_instance.yml -e "instance_name=$instance_name region=$region instance_type=$instance_type ami=$ami spot=$spot"
##awsdeletehost thursday --yes --region eu-central-1

echo RC: $?>> $HOME/aws/.start.log
