# 2026-06-23T14:30:53.346239400
import vitis

client = vitis.create_client()
client.set_workspace(path="AES256")

platform = client.get_component(name="platform")
domain = platform.get_domain(name="standalone_ps7_cortexa9_0")

