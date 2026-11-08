# SPDX-License-Identifier: MIT OR Apache-2.0
# Postern Container DPC app shell — SCAFFOLD, not built in this repo.
#
# The DeviceAdminReceiver is referenced by the framework by class name (declared in
# AndroidManifest.xml + res/xml/device_admin_receiver.xml), so it must survive
# shrinking if minification is ever enabled.
-keep class labs.postern.container.dpc.PosternDeviceAdminReceiver { *; }
