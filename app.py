#!/usr/bin/env python3
import os

import aws_cdk as cdk

from lattice_soln.lattice_soln_stack import LatticeSolnStack


app = cdk.App()
LatticeSolnStack(app, "LatticeSolnStack")
app.synth()
