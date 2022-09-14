#!/usr/bin/python3

import click
import boto3
import subprocess
import json


@click.group(help="Utility to using instances on ec2")
@click.option(
    "-p",
    "--profile",
    type=str,
    help="If no options are specified, the default profile is used.",
)
@click.pass_context
def cli(ctx, profile):
    if profile:
        ctx.params["session"] = boto3.Session(profile_name=profile)
    else:
        ctx.params["session"] = boto3.Session()

    ctx.params["client"] = ctx.params["session"].client("ec2")


@cli.command(help="EC2 start instance")
@click.option("-id", "--instance-id", type=str, help="specify instance id")
@click.option("-nt", "--name-tag", type=str, help="specify name tag")
@click.pass_context
def start(ctx, instance_id, name_tag):
    if name_tag:
        instance_id = ctx.invoke(instanceid, name_tag=name_tag)
    click.echo(instance_id)
    instance_ids = [instance_id] if instance_id else []
    r = ctx.parent.params["client"].start_instances(InstanceIds=instance_ids)
    data = json.dumps(r, ensure_ascii=False, indent=2)
    click.echo(data)


@cli.command(help="EC2 stop instance")
@click.option("-id", "--instance-id", type=str, help="specify instance id")
@click.option("-nt", "--name-tag", type=str, help="specify name tag")
@click.pass_context
def stop(ctx, instance_id, name_tag):
    if name_tag:
        instance_id = ctx.invoke(instanceid, name_tag=name_tag)
    click.echo(instance_id)
    instance_ids = [instance_id] if instance_id else []
    r = ctx.parent.params["client"].stop_instances(InstanceIds=instance_ids)
    data = json.dumps(r, ensure_ascii=False, indent=2)
    click.echo(data)


@cli.command(help="EC2 Describe-Instance-status")
@click.option("-id", "--instance-id", type=str, help="specify instance id")
@click.option("-nt", "--name-tag", type=str, help="specify name tag")
@click.option(
    "-d", "--detail", is_flag=True, help="EC2 Describe-Instance-status Detail"
)
@click.pass_context
def status(ctx, instance_id, name_tag, detail):
    if name_tag:
        instance_id = ctx.invoke(instanceid, name_tag=name_tag)
    instance_ids = [instance_id] if instance_id else []
    r = ctx.parent.params["client"].describe_instance_status(
        InstanceIds=instance_ids
    )
    if len(r["InstanceStatuses"]) == 0:
        click.echo("Nothing Data")
        return
    if detail:
        data = json.dumps(r, ensure_ascii=False, indent=2)
        click.echo(data)
    else:
        for statuses in r["InstanceStatuses"]:
            rdict = {
                "AvailabilityZone": statuses["AvailabilityZone"],
                "InstanceId": statuses["InstanceId"],
                "InstanceState": statuses["InstanceState"]["Name"],
            }
            data = json.dumps(rdict, ensure_ascii=False, indent=2)
            click.echo(data)


@cli.group(help="Show info")
@click.pass_context
def show(ctx):
    pass


@show.command(help="Show instance-id from name tag")
@click.option("-nt", "--name-tag", type=str, help="specify name tag")
@click.pass_context
def instanceid(ctx, name_tag):
    command = [
        "aws",
        "ec2",
        "describe-tags",
        "--filters",
        f"Name=tag:Name,Values={name_tag}",
        "Name=resource-type,Values=instance",
        "--query",
        "Tags[].ResourceId",
        "--output=text",
    ]
    res = subprocess.run(command, encoding="utf-8", stdout=subprocess.PIPE)
    response = str(res.stdout).strip()
    click.echo(response)
    return response


@show.command(help="Show group-id from security name tag")
@click.option("-nt", "--name-tag", type=str, help="specify security name tag")
@click.pass_context
def groupid(ctx, name_tag):
    command = [
        "aws",
        "ec2",
        "describe-security-groups",
        "--filters",
        f"Name=tag:Name,Values={name_tag}",
        "--query",
        "SecurityGroups[*].[GroupId]",
        "--output=text",
    ]
    res = subprocess.run(command, encoding="utf-8", stdout=subprocess.PIPE)
    response = str(res.stdout).strip()
    click.echo(response)
    return response


@show.command(help="Show GIP")
@click.pass_context
def gip(ctx):
    command = [
        "curl",
        "-s",
        "-k",
        "https://whatismyip.akamai.com/",
    ]
    res = subprocess.run(command, encoding="utf-8", stdout=subprocess.PIPE)
    response = str(res.stdout).strip()
    click.echo("GlobalIP: " + response)
    return response


@cli.group(help="EC2 Maintenance Security-Group")
@click.pass_context
def secg(ctx):
    pass


@secg.command(
    help="EC2 Add rule to Security-Group usage: \n\
        python ec2cli.py secg add -nt [Nametag]/-gid \
        [Group-id] --protocol [tcp/udp/icmp: Default tcp] \
        --port [PortNo: Default 22] \
        --cidr [0.0.0.0/32: Default Now Global IP]"
)
@click.option("-nt", "--name-tag", type=str, help="Security Name Tag")
@click.option("-gid", "--group-id", type=str, help="Group-id")
@click.option(
    "--protocol",
    type=str,
    default="tcp",
    help="Protocol (If no argument is set, tcp is set)",
)
@click.option(
    "--port",
    type=int,
    default=22,
    help="Port Number  (If no argument is set, 22 is set)",
)
@click.option(
    "--cidr",
    type=str,
    help="cidr  (If no argument is set, Now GIP is set)",
)
@click.pass_context
def add(ctx, name_tag, group_id, protocol, port, cidr):
    if name_tag:
        group_id = ctx.invoke(groupid, name_tag=name_tag)
    group_ids = group_id
    if cidr is None:
        cidr = ctx.invoke(gip) + "/32"
    r = ctx.parent.parent.params["client"].describe_security_groups(
        GroupIds=[group_ids]
    )
    flag = [
        1
        for sg in r["SecurityGroups"][0]["IpPermissions"]
        if sg["FromPort"] == port and sg["IpRanges"][0]["CidrIp"] == cidr
    ]

    if flag:
        click.echo("Rule already exists")
        return
    else:
        r = ctx.parent.parent.params[
            "client"
        ].authorize_security_group_ingress(
            GroupId=group_ids,
            IpPermissions=[
                {
                    "FromPort": port,
                    "IpProtocol": protocol,
                    "IpRanges": [
                        {
                            "CidrIp": cidr,
                        },
                    ],
                    "ToPort": port,
                },
            ],
        )
        data = json.dumps(r, ensure_ascii=False, indent=2)
        click.echo(data)


@secg.command(help="EC2 Add rule to Security-Group")
@click.option("-nt", "--name-tag", type=str, help="Security Name Tag")
@click.option("-gid", "--group-id", type=str, help="Group-id")
@click.option("--protocol", type=str, default="tcp", help="Protocol Type")
@click.option("--port", type=int, default=22, help="Port Number")
@click.option(
    "--cidr",
    type=str,
    help="cidr / if there is no cidr use Now GIP ",
)
@click.pass_context
def remove(ctx, name_tag, group_id, protocol, port, cidr):
    if name_tag:
        group_id = ctx.invoke(groupid, name_tag=name_tag)
    group_ids = group_id
    if cidr is None:
        cidr = ctx.invoke(gip) + "/32"
    r = ctx.parent.parent.params["client"].describe_security_groups(
        GroupIds=[group_ids]
    )
    flag = [
        1
        for sg in r["SecurityGroups"][0]["IpPermissions"]
        if sg["FromPort"] == port and sg["IpRanges"][0]["CidrIp"] == cidr
    ]

    if flag:
        r = ctx.parent.parent.params["client"].revoke_security_group_ingress(
            GroupId=group_ids,
            CidrIp=cidr,
            FromPort=port,
            IpProtocol=protocol,
            ToPort=port,
        )
        data = json.dumps(r, ensure_ascii=False, indent=2)
        click.echo(data)
        return
    else:
        click.echo("The rule you are trying to remove does not exist")
        return


@secg.command(help="EC2 Describe Security-Group")
@click.option("-nt", "--name-tag", type=str, help="Security Name Tag")
@click.option("-gid", "--group-id", type=str, help="Group-id")
@click.option(
    "-d", "--detail", is_flag=True, help="EC2 Describe Security-Group Detail"
)
@click.pass_context
def list(ctx, name_tag, group_id, detail):
    if name_tag:
        group_id = ctx.invoke(groupid, name_tag=name_tag)
    group_ids = [group_id] if group_id else []
    r = ctx.parent.parent.params["client"].describe_security_groups(
        GroupIds=group_ids
    )
    if len(r) == 0:
        click.echo("Nothing Data")
        return
    if detail:
        data = json.dumps(r["SecurityGroups"], ensure_ascii=False, indent=2)
        click.echo(data)
    else:
        for secglist in r["SecurityGroups"]:
            for ippermissions in secglist["IpPermissions"]:
                rdict = {
                    "FromPort": ippermissions["FromPort"],
                    "IpProtocol": ippermissions["IpProtocol"],
                    "CidrIP": ippermissions["IpRanges"][0]["CidrIp"],
                    "ToPort": ippermissions["ToPort"],
                }
                data = json.dumps(rdict, ensure_ascii=False, indent=2)
                click.echo(data)


def main():
    cli()


if __name__ == "__main__":
    main()
