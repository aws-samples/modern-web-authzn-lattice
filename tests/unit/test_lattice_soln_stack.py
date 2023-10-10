import aws_cdk as core
import aws_cdk.assertions as assertions

from lattice_soln.lattice_soln_stack import LatticeSolnStack

# example tests. To run these tests, uncomment this file along with the example
# resource in lattice_soln/lattice_soln_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = LatticeSolnStack(app, "lattice-soln")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
