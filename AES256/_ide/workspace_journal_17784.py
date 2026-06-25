# 2026-06-23T16:00:34.474812800
import vitis

client = vitis.create_client()
client.set_workspace(path="AES256")

platform = client.get_component(name="platform")
status = platform.delete_domain(name="KarunOS")

status = platform.build()

vitis.dispose()

client.delete_component(name="app_component")

comp = client.create_app_component(name="app_component",platform = "$COMPONENT_LOCATION/../platform/export/platform/platform.xpfm",domain = "standalone_ps7_cortexa9_0")

comp = client.get_component(name="app_component")
status = comp.import_files(from_loc="", files=["C:\Users\hp\Downloads\Internship\Extended\ps\src\main.c"], is_skip_copy_sources = False)

platform = client.get_component(name="platform")
status = platform.build()

comp = client.get_component(name="app_component")
comp.build()

comp = client.get_component(name="app_component")
status = comp.import_files(from_loc="$COMPONENT_LOCATION/../../ps/src", files=["platform.h"], dest_dir_in_cmp = "src", is_skip_copy_sources = False)

status = platform.build()

comp = client.get_component(name="app_component")
comp.build()

vitis.dispose()

