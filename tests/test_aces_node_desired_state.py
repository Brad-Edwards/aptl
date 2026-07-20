"""The node realization carries the declared ACES desired state (ADR-048).

`_realize_node` extracts `os`/`os_version` and reconstructs the typed
`RuntimeConfiguration` from the node payload so the generic materializer can
realize it. Malformed/absent runtime returns None rather than aborting.
"""

from __future__ import annotations

from aptl.backends.aces_realization import (
    _node_os,
    _node_os_version,
    _node_runtime,
)
from aptl.backends.aces_realization_model import NodeRealization


class TestExtraction:
    def test_os_and_version(self):
        node_spec = {"os": "linux", "os_version": "debian12"}
        assert _node_os(node_spec) == "linux"
        assert _node_os_version(node_spec) == "debian12"
        assert _node_os(None) == "" and _node_os_version(None) == ""

    def test_runtime_reconstructed_as_typed_model(self):
        node_spec = {
            "runtime": {
                "packages": [{"manager": "apt", "name": "curl", "version": "*"}],
                "service_manager_units": [
                    {
                        "unit_id": "svc",
                        "unit_name": "svc.service",
                        "active_state": "active",
                    }
                ],
            }
        }
        runtime = _node_runtime(node_spec)
        assert runtime is not None
        assert runtime.packages[0].name == "curl"
        assert runtime.service_manager_units[0].unit_name == "svc.service"

    def test_absent_or_malformed_runtime_is_none(self):
        assert _node_runtime(None) is None
        assert _node_runtime({}) is None
        assert _node_runtime({"runtime": "not-a-mapping"}) is None
        # A structurally invalid runtime does not abort realization.
        assert _node_runtime({"runtime": {"packages": "nope"}}) is None


class TestSerialization:
    def test_details_summarizes_desired_state_without_secrets(self):
        node_spec = {
            "os": "linux",
            "runtime": {
                "packages": [{"manager": "apt", "name": "curl", "version": "*"}],
            },
        }
        node = NodeRealization(
            address="n.node",
            name="node",
            aliases=(),
            profiles=(),
            backend_services=(),
            container_name=None,
            services=(),
            networks=(),
            static_addresses=(),
            os="linux",
            runtime=_node_runtime(node_spec),
        )
        details = node.details()
        assert details["os"] == "linux"
        assert details["runtime"]["packages"] == 1


class TestImageFreeDerivation:
    def _node(self, *, os="linux", runtime=..., image=None):
        from aces_sdl.runtime_configuration import RuntimeConfiguration
        rt = RuntimeConfiguration() if runtime is ... else runtime
        return NodeRealization(
            address="n." + (os or "sw"), name="n", aliases=(), profiles=(),
            backend_services=(), container_name=None, services=(), networks=(),
            static_addresses=(), os=os, runtime=rt, image=image,
        )

    def test_all_os_nodes_have_runtime_and_no_images_is_image_free(self):
        from aptl.backends.aces_realization_model import _realization_is_image_free
        assert _realization_is_image_free((self._node(), self._node())) is True

    def test_any_appliance_image_is_not_image_free(self):
        from aptl.backends.aces_realization_model import _realization_is_image_free
        # Any non-None image marks a node as appliance-image realized.
        assert _realization_is_image_free((self._node(image=object()),)) is False

    def test_os_node_without_runtime_is_not_image_free(self):
        from aptl.backends.aces_realization_model import _realization_is_image_free
        assert _realization_is_image_free((self._node(runtime=None),)) is False

    def test_no_os_nodes_is_not_image_free(self):
        from aptl.backends.aces_realization_model import _realization_is_image_free
        assert _realization_is_image_free((self._node(os=""),)) is False
