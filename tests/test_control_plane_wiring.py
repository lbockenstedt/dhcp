"""Standalone entrypoint wiring.

REGRESSION (review #3): ``DHCPSpoke``'s HA transport resolves its control plane
through ``self.control_plane``, and the plane consults the module's
``cluster_listener_required()`` the moment it is registered. Registering first
left a window in which the module was live on the hub connection but had no
plane to reach its Kea workers through.
"""

import ast
import os

MAIN = os.path.join(os.path.dirname(__file__), "..", "src", "main.py")


def _run_body():
    tree = ast.parse(open(MAIN, encoding="utf-8").read())
    cls = next(n for n in ast.walk(tree)
               if isinstance(n, ast.ClassDef) and n.name == "DHCPControlPlane")
    run = next(n for n in cls.body
               if isinstance(n, ast.AsyncFunctionDef) and n.name == "run")
    return run.body


def _line_of(body, needle):
    for node in body:
        if needle in ast.dump(node):
            return node.lineno
    raise AssertionError(f"{needle} not found in run()")


def test_control_plane_is_attached_before_the_module_is_registered():
    body = _run_body()
    attach = _line_of(body, "attr='control_plane'")
    register = _line_of(body, "attr='register_module'")
    assert attach < register, \
        "module.control_plane must be set BEFORE register_module"


def test_the_listener_is_started_after_registration():
    body = _run_body()
    register = _line_of(body, "attr='register_module'")
    listener = _line_of(body, "_agent_listener_enabled")
    assert register < listener
