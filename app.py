#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import os

import aws_cdk as cdk

from lattice_soln.lattice_soln_stack import LatticeSolnStack


app = cdk.App()
LatticeSolnStack(app, "LatticeSolnStack")
app.synth()
