# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from aws_cdk import (
    Stack,
)
from aws_cdk import (
    aws_ec2 as ec2,
    aws_ecs as ecs,
    aws_ecs_patterns as ecs_patterns,
    CfnParameter,
    aws_autoscaling as autoscaling,
    aws_iam as iam,
    aws_vpclattice as vpclattice,
    aws_route53 as route53,
    aws_route53_targets as targets,
)

from aws_cdk.aws_ecr_assets import DockerImageAsset, Platform

from urllib.parse import urlparse

from constructs import Construct

import sys
import os
from aws_cdk.aws_ec2 import IPrefixList, PrefixList
from aws_cdk.custom_resources import (
    AwsCustomResource,
    AwsCustomResourcePolicy,
    PhysicalResourceId,
)
from constructs import Construct

from aws_cdk.aws_ec2 import IPrefixList, PrefixList
from aws_cdk.aws_iam import Effect, PolicyStatement
from aws_cdk.custom_resources import (
    AwsCustomResource,
    AwsCustomResourcePolicy,
    PhysicalResourceId,
)
from constructs import Construct


# Supporting classes to retrieve prefix list ID
class AwsManagedPrefixList(Construct):
    def __init__(self, scope: Construct, id: str, name: str):
        super().__init__(scope, id)
        prefixListId = AwsCustomResource(
            self,
            "GetPrefixListId",
            on_update={
                "service": "@aws-sdk/client-ec2",
                "action": "DescribeManagedPrefixListsCommand",
                "parameters": {
                    "Filters": [
                        {
                            "Name": "prefix-list-name",
                            "Values": [name],
                        },
                    ],
                },
                "physical_resource_id": PhysicalResourceId.of(
                    f"{id}-{self.node.addr[:16]}"
                ),
            },
            policy=AwsCustomResourcePolicy.from_statements(
                [
                    PolicyStatement(
                        effect=Effect.ALLOW,
                        actions=["ec2:DescribeManagedPrefixLists"],
                        resources=["*"],
                    ),
                ]
            ),
        ).get_response_field("PrefixLists.0.PrefixListId")

        self.prefixList = PrefixList.from_prefix_list_id(
            self, "PrefixList", prefixListId
        )


class LatticeSolnStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Our parameters that are used to configure envoy jwt handling and the domain we use for the application

        # Default we don't enable OAuth features
        enable_oauth = False

        enable_oauth = self.node.try_get_context("enable_oauth")
        app_domain = self.node.try_get_context("app_domain")
        if app_domain == None:
            raise ValueError(
                """
                Specify app_domain context when calling cdk synth or deploy
                eg: cdk deploy -c app_domain=application.internal
                            """
            )

        if enable_oauth:
            jwt_jwks = self.node.try_get_context("jwt_jwks")
            if jwt_jwks == None:
                raise ValueError(
                    """
                    Specify jwt_jwks context when calling cdk synth or deploy
                    eg: cdk deploy -c jwt_jwks=https://dev-123456.okta.com/oauth2/ausa1234567/v1/keys -c jwt_issuer=https://dev-123456.okta.com/oauth2/ausa1234567 -c jwt_audience=example -c app_domain=application.internal
                                """
                )
            jwt_issuer = self.node.try_get_context("jwt_issuer")
            if jwt_issuer == None:
                raise ValueError(
                    """
                    Specify jwt_issuer context when calling cdk synth or deploy
                    eg: cdk deploy -c jwt_jwks=https://dev-123456.okta.com/oauth2/ausa1234567/v1/keys -c jwt_issuer=https://dev-123456.okta.com/oauth2/ausa1234567 -c jwt_audience=example -c app_domain=application.internal
                                """
                )
            jwt_audience = self.node.try_get_context("jwt_audience")
            if jwt_audience == None:
                raise ValueError(
                    """
                    Specify jwt_audience context when calling cdk synth or deploy
                    eg: cdk deploy -c jwt_jwks=https://dev-123456.okta.com/oauth2/ausa1234567/v1/keys -c jwt_issuer=https://dev-123456.okta.com/oauth2/ausa1234567 -c jwt_audience=example -c app_domain=application.internal
                                """
                )

            # Environment configuration for our envoy and app server containers
            envoy_frontend_env = {}
            envoy_frontend_env["JWT_JWKS"] = jwt_jwks
            envoy_frontend_env["JWT_ISSUER"] = jwt_issuer
            envoy_frontend_env["APP_DOMAIN"] = app_domain
            envoy_frontend_env["JWT_AUDIENCE"] = jwt_audience
            envoy_frontend_env["JWKS_HOST"] = urlparse(
                envoy_frontend_env["JWT_JWKS"]
            ).hostname
            envoy_frontend_env["DEPLOY_REGION"] = Stack.of(self).region

        application_env = {}
        application_env["HTTP_PORT"] = "80"
        application_env["DEPLOY_REGION"] = Stack.of(self).region

        private_subnet_configuration = [ 
                ec2.SubnetConfiguration( cidr_mask=26, name="private1", subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS ), 
                ec2.SubnetConfiguration( cidr_mask=26, name="private2", subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS ), 
                ec2.SubnetConfiguration( cidr_mask=26, name="private3", subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS ),
        ]
        public_subnet_configuration = [
                ec2.SubnetConfiguration( cidr_mask=26, name="public1", subnet_type=ec2.SubnetType.PUBLIC ), 
                ec2.SubnetConfiguration( cidr_mask=26, name="public2", subnet_type=ec2.SubnetType.PUBLIC ), 
                ec2.SubnetConfiguration( cidr_mask=26, name="public3", subnet_type=ec2.SubnetType.PUBLIC )
        ]

        # Create a new VPC
        vpc = ec2.Vpc(self, "LatticeSolnVPC", 
            subnet_configuration= private_subnet_configuration.extend(public_subnet_configuration),
                max_azs=3)

        # Create a new hosted zone for our domain
        zone = route53.PrivateHostedZone(
            self, "HostedZone", zone_name=app_domain, vpc=vpc
        )

        # Create a lattice service network with IAM Authentication enabled
        servicenetwork = vpclattice.CfnServiceNetwork(
            self,
            "LatticeServiceNetwork",
            auth_type="AWS_IAM",
        )

        # Associate the lattice service network with the previously created VPC
        servicenetworkassociation = vpclattice.CfnServiceNetworkVpcAssociation(
            self,
            "LatticeVPCAssociation",
            service_network_identifier=servicenetwork.attr_arn,
            vpc_identifier=vpc.vpc_id,
        )

        # Create an ECS cluster in our VPC
        cluster = ecs.Cluster(self, "LatticeSolnCluster", vpc=vpc)

        # Create an autoscaling group to run our ECS containers
        ecs_asg_role = iam.Role(
            self,
            "ECSAsgRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            description="ECS Autoscaling Group Role",
        )
        ecs_asg_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "AmazonSSMManagedInstanceCore"
            )
        )

        auto_scaling_group = autoscaling.AutoScalingGroup(
            self,
            "LatticeSolnAsg",
            vpc=vpc,
            instance_type=ec2.InstanceType("m5.large"),
            machine_image=ecs.EcsOptimizedImage.amazon_linux2(),
            desired_capacity=3,
            role=ecs_asg_role,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
        )

        capacity_provider = ecs.AsgCapacityProvider(
            self, "AsgCapacityProvider", auto_scaling_group=auto_scaling_group
        )

        # Add the autoscaling group to our ECS cluster so we can schedule continers
        cluster.add_asg_capacity_provider(capacity_provider)
        # Create a list of roles, that can be used in our lattice servicenetwork and service policies
        roles = {}

        if enable_oauth:
            # Create an IAM role for the frontend envoy task
            envoy_frontend_task_role = iam.Role(
                self,
                "EnvoyFrontendTaskRole",
                assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            )

            roles["envoy-frontend"] = envoy_frontend_task_role

            # Give envoy the permission to invoke vpc lattice services
            envoy_frontend_task_role.attach_inline_policy(
                iam.Policy(
                    self,
                    "EnvoyFrontendTaskPolicy",
                    statements=[
                        iam.PolicyStatement(
                            actions=["vpc-lattice-svcs:Invoke"],
                            resources=["*"],
                            conditions={
                                "StringEquals": {
                                    "vpc-lattice-svcs:ServiceNetworkArn": servicenetwork.attr_arn
                                }
                            },
                        )
                    ],
                )
            )

            # Creaate a new task definition for envoy and add in the container we build from containers/envoy directory
            envoy_frontend_task_definition = ecs.Ec2TaskDefinition(
                self,
                "envoy-frontend-task",
                network_mode=ecs.NetworkMode.AWS_VPC,
                task_role=envoy_frontend_task_role,
            )

            envoy_frontend_asset = DockerImageAsset(
                self,
                "envoy_frontend",
                directory=os.path.join(
                    os.path.dirname(os.path.realpath(__file__)), "containers/envoy"
                ),
                asset_name="envoy_frontend",
                platform=Platform.LINUX_AMD64,
            )

            envoy_frontend_task_definition.add_container(
                "envoy-frontend",
                image=ecs.ContainerImage.from_docker_image_asset(envoy_frontend_asset),
                cpu=512,
                memory_limit_mib=2048,
                essential=True,
                environment=envoy_frontend_env,
                logging=ecs.AwsLogDriver.aws_logs(stream_prefix="envoy-frontend"),
                port_mappings=[ecs.PortMapping(container_port=80)],
            )

            # Create an ECS service, with a load balancer, using the envoy task definition
            frontendalbservice = ecs_patterns.ApplicationLoadBalancedEc2Service(
                self,
                "envoy-frontend",
                cluster=cluster,
                cpu=1024,
                desired_count=2,
                task_definition=envoy_frontend_task_definition,
                memory_limit_mib=2048,
                public_load_balancer=False,
            )

            # Change the load balancer configuration to use /health for health checking envoy
            frontendalbservice.target_group.configure_health_check(path="/health")

            # Add a generic domain A record pointing to the frontend envoy load balancer, used for client communications
            route53.ARecord(
                self,
                app_domain,
                record_name=app_domain,
                zone=zone,
                target=route53.RecordTarget.from_alias(
                    targets.LoadBalancerTarget(frontendalbservice.load_balancer)
                ),
            )

        # Create a security group for all of our application containers, with inbound access from the lattice Prefix List
        # This is done via looking up managed prefix list with name com.amazonaws.ap-southeast-2.vpc-lattice or equivalent for
        # the region you are deploying the stack to

        latticesecuritygroup = ec2.SecurityGroup(self, "latticeSecurityGroup", vpc=vpc)
        latticeprefixlist = AwsManagedPrefixList(
            self,
            "LatticePrefixList",
            name="com.amazonaws." + Stack.of(self).region + ".vpc-lattice",
        ).prefixList

        latticesecuritygroup.add_ingress_rule(
            ec2.Peer.prefix_list(latticeprefixlist.prefix_list_id),
            ec2.Port.tcp(80),
            "http inbound from lattice",
        )

        # Build the docker container for our app server. This is reused in three task definitions, one for each app component
        webserver_asset = DockerImageAsset(
            self,
            "webserver",
            directory=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "containers/app"
            ),
            asset_name="webserver",
            platform=Platform.LINUX_AMD64,
            build_args={"no-cache":"true"}
        )

        for name in ("app1", "app2", "app3"):
            # Create an iam role for the task running the app. This allows the task to perform sigv4 signing to access lattice
            id = name + "TaskRole"
            app_role = iam.Role(
                self,
                id,
                assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            )

            app_role.attach_inline_policy(
                iam.Policy(
                    self,
                    name + "TaskPolicy",
                    statements=[
                        iam.PolicyStatement(
                            actions=["vpc-lattice-svcs:Invoke"],
                            resources=["*"],
                            conditions={
                                "StringEquals": {
                                    "vpc-lattice-svcs:ServiceNetworkArn": servicenetwork.attr_arn
                                }
                            },
                        )
                    ],
                )
            )
            # Store the new task role to our list
            roles[name] = app_role

        for name in ("app1", "app2", "app3"):
            # Create a task definition for our app component
            task_definition = ecs.Ec2TaskDefinition(
                self,
                name + "-task",
                network_mode=ecs.NetworkMode.AWS_VPC,
                task_role=roles[name],
            )

            application_env['WEBSERVER']=name
            docker_labels={}
            docker_labels['webserver']=name
            task_definition.add_container(
                name + "-container",
                image=ecs.ContainerImage.from_docker_image_asset(webserver_asset),
                cpu=256,
                memory_limit_mib=256,
                essential=True,
                environment=application_env,
                logging=ecs.AwsLogDriver.aws_logs(stream_prefix=name),
                port_mappings=[ecs.PortMapping(container_port=80)],
                docker_labels=docker_labels
            )

            # Create a load balanced ECS service for each app component
            service = ecs_patterns.ApplicationLoadBalancedEc2Service(
                self,
                name + "-service",
                cluster=cluster,
                cpu=1024,
                desired_count=1,
                open_listener=False,
                task_definition=task_definition,
                memory_limit_mib=2048,
                public_load_balancer=False,
            )

            # Restrict access to the load balancer from lattice only. This prevents bypassing lattice and accessing the service directly
            service.load_balancer.add_security_group(latticesecuritygroup)

            # Create a lattice service for our new app component, with IAM authentication
            latticeservice = vpclattice.CfnService(
                self,
                name + "-LatticeService",
                dns_entry=vpclattice.CfnService.DnsEntryProperty(
                    domain_name=name + "." + app_domain,
                    hosted_zone_id=zone.hosted_zone_id,
                ),
                custom_domain_name=name + "." + app_domain,
                auth_type="AWS_IAM",
            )

            authpolicy = iam.PolicyDocument()

            # Create our lattice service policy
            match name:
                case "app1":
                    # app1 policy allows application app2 to call
                    statements = [
                        iam.PolicyStatement(
                            actions=["vpc-lattice-svcs:Invoke"],
                            principals=[iam.ArnPrincipal(roles["app2"].role_arn)],
                            resources=[latticeservice.attr_arn + "/*"],
                        )
                    ]
                    if enable_oauth:
                    # app1 policy allows clients with scope test.all to call
                        statements.append(
                            iam.PolicyStatement(
                                actions=["vpc-lattice-svcs:Invoke"],
                                principals=[
                                    iam.ArnPrincipal(roles["envoy-frontend"].role_arn)
                                ],
                                resources=[latticeservice.attr_arn + "/*"],
                                conditions={
                                    "StringEquals": {
                                        "vpc-lattice-svcs:RequestHeader/x-jwt-scope-test.all": "true"
                                    }
                                },
                            )
                        )
                    authpolicy = iam.PolicyDocument(statements=statements)
                case "app2":
                    # app2 policy only allows clients with scope test.all
                    if enable_oauth:
                        statements = [
                            iam.PolicyStatement(
                                actions=["vpc-lattice-svcs:Invoke"],
                                principals=[
                                    iam.ArnPrincipal(roles["envoy-frontend"].role_arn)
                                ],
                                resources=[latticeservice.attr_arn + "/*"],
                                conditions={
                                    "StringEquals": {
                                        "vpc-lattice-svcs:RequestHeader/x-jwt-scope-test.all": "true"
                                    }
                                },
                            )
                        ]
                    else:
                        statements = [
                            iam.PolicyStatement(
                                effect=iam.Effect.DENY,
                                actions=["*"],
                                principals=[iam.AnyPrincipal()],
                                resources=[latticeservice.attr_arn + "/*"],
                            )
                        ]

                    authpolicy = iam.PolicyDocument(statements=statements)
                case "app3":
                    # no auth policy for app3
                    authpolicy = iam.PolicyDocument(
                        statements=[
                            iam.PolicyStatement(
                                effect=iam.Effect.DENY,
                                actions=["*"],
                                principals=[iam.AnyPrincipal()],
                                resources=[latticeservice.attr_arn + "/*"],
                            )
                        ]
                    )

            servicepolicy = vpclattice.CfnAuthPolicy(
                self,
                name + "LatticeServicePolicy",
                resource_identifier=latticeservice.attr_arn,
                policy=authpolicy,
            )

            # Associate the lattice service with our service network
            vpclattice.CfnServiceNetworkServiceAssociation(
                self,
                name + "-ServiceAssociation",
                service_network_identifier=servicenetwork.attr_arn,
                service_identifier=latticeservice.attr_arn,
            )

            # Link the lattice target group to our newly created load balancer
            LatticeTargetGroup = vpclattice.CfnTargetGroup(
                self,
                id=name + "-LatticeTargetGroup",
                type="ALB",
                config=vpclattice.CfnTargetGroup.TargetGroupConfigProperty(
                    port=80, protocol="HTTP", vpc_identifier=vpc.vpc_id
                ),
                targets=[
                    vpclattice.CfnTargetGroup.TargetProperty(
                        id=service.load_balancer.load_balancer_arn,
                    )
                ],
            )

            # Create our route53 cname to redirect the application names to our matching lattice service
            route53.CnameRecord(
                self,
                name + "-cname",
                record_name=name,
                zone=zone,
                domain_name=latticeservice.attr_dns_entry_domain_name,
            )

            # Create our lattice listener for this app component
            vpclattice.CfnListener(
                self,
                name + "-LatticeListener",
                protocol="HTTP",
                default_action=vpclattice.CfnListener.DefaultActionProperty(
                    forward=vpclattice.CfnListener.ForwardProperty(
                        target_groups=[
                            vpclattice.CfnListener.WeightedTargetGroupProperty(
                                target_group_identifier=LatticeTargetGroup.attr_id
                            )
                        ]
                    )
                ),
                port=80,
                service_identifier=latticeservice.attr_id,
            )

        # Create our overarching service network policy using the task roles we defined in 'roles' above
        arnprincipals = []
        for i in list(roles.values()):
            arnprincipals.append(iam.ArnPrincipal(i.role_arn))

        authpolicy = iam.PolicyDocument(
            statements=[
                iam.PolicyStatement(
                    actions=["vpc-lattice-svcs:Invoke"],
                    principals=arnprincipals,
                    resources=["*"],
                )
            ]
        )

        servicenetworkpolicy = vpclattice.CfnAuthPolicy(
            self,
            "LatticeServiceNetworkPolicy",
            resource_identifier=servicenetwork.attr_arn,
            policy=authpolicy,
        )
