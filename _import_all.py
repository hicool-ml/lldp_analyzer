# Auto-generated: imports all project modules so PyInstaller includes them.
# Platform-specific backends are wrapped in try/except to prevent
# ImportError on non-target platforms (e.g. windows adapter on macOS).

import utils.__init__  # noqa: F401
import utils.adapter_scanner  # noqa: F401
import utils.capture_engine  # noqa: F401
import utils.elevator  # noqa: F401
import utils.hexdump  # noqa: F401
import utils.interface_finder  # noqa: F401
import utils.link_monitor  # noqa: F401
import utils.lldp_sender  # noqa: F401
import utils.packet_capture  # noqa: F401
import utils.platform_utils  # noqa: F401
import utils.protocol_parser  # noqa: F401
import decoders.__init__  # noqa: F401
import decoders.cisco_decoder  # noqa: F401
import decoders.h3c_decoder  # noqa: F401
import decoders.huawei_decoder  # noqa: F401
import decoders.juniper_decoder  # noqa: F401
import decoders.ruijie_decoder  # noqa: F401
import network.__init__  # noqa: F401
import network.backend  # noqa: F401
import network.engine  # noqa: F401
import network.platform  # noqa: F401
import network.elevated_op  # noqa: F401
import network.backends.__init__  # noqa: F401
import network.core.interfaces  # noqa: F401
try:
    import network.backends.windows.adapter  # noqa: F401
except ImportError:
    pass  # Windows-only; not available on macOS/Linux
try:
    import network.backends.macos.adapter  # noqa: F401
except ImportError:
    pass  # macOS-only
try:
    import network.backends.posix.adapter  # noqa: F401
except ImportError:
    pass  # Linux-only
