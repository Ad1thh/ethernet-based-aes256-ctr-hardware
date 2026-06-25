# 2026-06-23T13:59:52.170706200
import vitis

client = vitis.create_client()
client.set_workspace(path="AES256")

platform = client.create_platform_component(name = "platform",hw_design = "$COMPONENT_LOCATION/../design_1_wrapper.xsa",os = "standalone",cpu = "ps7_cortexa9_0",domain_name = "standalone_ps7_cortexa9_0",compiler = "gcc")

platform = client.get_component(name="platform")
status = platform.build()

comp = client.create_app_component(name="app_component",platform = "$COMPONENT_LOCATION/../platform/export/platform/platform.xpfm",domain = "standalone_ps7_cortexa9_0")

comp = client.get_component(name="app_component")
status = comp.import_files(from_loc="", files=["C:\Users\hp\Downloads\Internship\Extended\ps\src\aes256_sw.c", "C:\Users\hp\Downloads\Internship\Extended\ps\src\main.c", "C:\Users\hp\Downloads\Internship\Extended\ps\src\platform.c", "C:\Users\hp\Downloads\Internship\Extended\ps\src\platform.h", "C:\Users\hp\Downloads\Internship\Extended\ps\src\aes256_sw.h"], is_skip_copy_sources = False)

status = platform.build()

comp = client.get_component(name="app_component")
comp.build()

domain = platform.get_domain(name="zynq_fsbl")

status = domain.set_lib(lib_name="lwip220", path="C:\AMDDesignTools\2025.2.1\Vitis\data\embeddedsw\ThirdParty\sw_services\lwip220_v1_3")

status = platform.build()

status = platform.build()

comp.build()

status = domain.regenerate()

status = platform.build()

status = platform.build()

comp.build()

status = platform.build()

comp.build()

client.delete_component(name="app_component")

client.delete_component(name="componentName")

domain = platform.add_domain(cpu = "ps7_cortexa9_1",os = "standalone",name = "KarunOS",display_name = "KarunOS",generate_dtb = False,hw_boot_bin = "")

comp = client.create_app_component(name="app_component",platform = "$COMPONENT_LOCATION/../platform/export/platform/platform.xpfm",domain = "KarunOS")

comp = client.get_component(name="app_component")
status = comp.import_files(from_loc="", files=["C:\Users\hp\Downloads\Internship\Extended\ps\src\main.c"], is_skip_copy_sources = False)

status = platform.build()

status = platform.build()

comp = client.get_component(name="app_component")
comp.build()

