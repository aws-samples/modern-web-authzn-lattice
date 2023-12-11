
# Modern Web Authentication/Authorization with AWS VPC Lattice

This repository accompanies the blog post <blogURL>

It will deploy the following components:

* A VPC with associated subnets, NAT Gateways and Internet Gateway. Internet access is required so the solution is able to retrieve JWKS details from your OAuth Provider.
* Route53 hosted zone for handling traffic routing to the configured domain and VPC Lattice services.
* ECS Cluster (default 2 container hosts) to run the ECS tasks
* 4 Application Load Balancers, one for front-end envoy routing and one for each application component. 
    * All application load balancers are internally facing.
    * Application component load balancers are configured to only accept traffic from the VPC Lattice Managed Prefix List.
    * The front-end envoy load balancer is configured to accept traffic from any host 
* 3 VPC Lattice Services and 1 VPC Lattice Network.

The repository demonstrates some novel and reusable solution components:

* JWT Authorization and translation of scopes to headers, integrating an external IdP into our solution for user authentication.
* SigV4 signing from an Envoy Proxy running in a container.
* Service to service flows, using SigV4 signing in node.js and container based credentials.
* Integration of VPC Lattice with ECS containers, using CDK

Note: This solution is intended as sample code only, and not for production use. In particular, it does not implement TLS and the sample application will echo the contents of the request back to the caller.