"""AST-based analysis for Python targets.

The regex detectors are fast and language-agnostic but blind to distance and
dataflow. This package adds precise, stdlib-only (`ast`) analysis for Python:
which functions are exposed to the model as tools, and whether a dangerous sink
actually sits inside one — regardless of how far it is from the registration.
"""
