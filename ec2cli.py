import click
import boto3
import subprocess
import json


@click.group(help="Utility to using instances on ec2")
@click.option("-p", "--profile", type=str)
@click.pass_context
def cli(ctx, profile):
    if ctx.params.get("profile") is None:
        ctx.params["session"] = boto3.Session()
    else:
        ctx.params["session"] = boto3.session.Session(
            profile_name=ctx.params.get("profile")
        )
    ctx.params["client"] = ctx.params["session"].client("ec2")


@cli.command(help="EC2 start instance")
@click.option("-id", "--instance-id", type=str, help="specify instance id")
@click.option("-nt", "--name-tag", type=str, help="specify name tag")
@click.pass_context
def start(ctx, instance_id, name_tag):
    if ctx.params.get("name_tag"):
        instance_id = tag_to_instanceid(ctx.params.get("name_tag"))
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
    if ctx.params.get("name_tag"):
        instance_id = tag_to_instanceid(ctx.params.get("name_tag"))
    click.echo(instance_id)
    instance_ids = [instance_id] if instance_id else []
    r = ctx.parent.params["client"].stop_instances(InstanceIds=instance_ids)
    data = json.dumps(r, ensure_ascii=False, indent=2)
    click.echo(data)


def tag_to_instanceid(name_tag):
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
    return response


def tag_to_securityid(name_tag):
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
    return response


@cli.command(help="Show GIP")
@click.option("-s", "--show", is_flag=True, help="Show GlobalIP")
@click.pass_context
def myip(ctx, show):
    command = [
        "curl",
        "-s",
        "-k",
        "https://whatismyip.akamai.com/",
    ]
    res = subprocess.run(command, encoding="utf-8", stdout=subprocess.PIPE)
    response = str(res.stdout).strip()
    if show:
        click.echo(response)
    return response


@cli.command(help="EC2 Describe-Instance-status")
@click.option("-id", "--instance-id", type=str, help="specify instance id")
@click.option("-nt", "--name-tag", type=str, help="specify name tag")
@click.option(
    "-d", "--detail", is_flag=True, help="EC2 Describe-Instance-status Detail"
)
@click.pass_context
def status(ctx, instance_id, name_tag, detail):
    if ctx.params.get("name_tag"):
        instance_id = tag_to_instanceid(ctx.params.get("name_tag"))
    instance_ids = [instance_id] if instance_id else []
    r = ctx.parent.params["client"].describe_instance_status(
        InstanceIds=instance_ids
    )
    if not r["InstanceStatuses"]:
        click.echo("Nothing Data")
        return
    if detail:
        data = json.dumps(r, ensure_ascii=False, indent=2)
    else:
        for statuses in r["InstanceStatuses"]:
            rdict = {
                "AvailabilityZone": statuses["AvailabilityZone"],
                "InstanceId": statuses["InstanceId"],
                "InstanceState": statuses["InstanceState"]["Name"],
            }
        data = json.dumps(rdict, ensure_ascii=False, indent=2)
    click.echo(data)


@cli.group(help="EC2 Maintenance Security-Group")
@click.pass_context
def sg(ctx):
    pass


@sg.command(help="EC2 Add rule to Security-Group")
@click.option("-nt", "--name-tag", type=str, help="Security Name Tag")
@click.option("-gid", "--group-id", type=str, help="Group-id")
@click.option("--protocol", type=str, default="all", help="Protocol Type")
@click.option("--port", type=str, default="all", help="Port Number")
@click.option(
    "--cidr",
    type=str,
    is_flag=True,
    help="cidr / if there is no cidr use Now GIP ",
)
@click.pass_context
def add(ctx, name_tag, group_id, protocol, port, cidr):
    click.echo(ctx.params.get("name_tag"))
    if ctx.params.get("name_tag"):
        group_id = tag_to_securityid(ctx.params.get("name_tag"))
    group_ids = [group_id] if group_id else []
    if cidr is None:
        cidr = ctx.invoke(myip)
    click.echo(group_ids)
    data = ctx.parent.parent.params["client"].authorize_security_group_ingress(
        GroupIds=group_ids,
        IpPermissions=[
            {
                "FromPort": ctx.params.get("port"),
                "IpProtocol": ctx.params.get("protocol"),
                "IpRanges": [
                    {
                        "CidrIp": cidr,
                        "Description": "",
                    },
                ],
                "ToPort": ctx.params.get("port"),
            },
        ],
    )
    click.echo(json.dumps(data, ensure_ascii=False, indent=2))


@sg.command(help="EC2 Describe Security-Group")
@click.option("-nt", "--name-tag", type=str, help="Security Name Tag")
@click.option("-gid", "--group-id", type=str, help="Group-id")
@click.option(
    "-d", "--detail", is_flag=True, help="EC2 Describe Security-Group Detail"
)
@click.pass_context
def list(ctx, name_tag, group_id, detail):
    if ctx.params.get("name_tag"):
        group_id = tag_to_securityid(ctx.params.get("name_tag"))
    group_ids = [group_id] if group_id else []
    r = ctx.parent.parent.params["client"].describe_security_groups(
        GroupIds=group_ids
    )
    if r is None:
        click.echo("Nothing Data")
        return
    if detail:
        data = json.dumps(r["SecurityGroups"], ensure_ascii=False, indent=2)
    else:
        for secglist in r["SecurityGroups"]:
            for ippermissions in secglist["IpPermissions"]:
                for cidrip in ippermissions["IpRanges"]:
                    data = cidrip["CidrIp"]
    click.echo(data)


def main():
    cli()


if __name__ == "__main__":
    main()
