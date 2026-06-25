# 2026-06-24T13:49:53.868816900
import vitis

client = vitis.create_client()
client.set_workspace(path="AES256")

platform = client.get_component(name="platform")
status = platform.build()

comp = client.get_component(name="app_component")
comp.build()

status = platform.build()

comp.build()

status = platform.build()

comp.build()

status = platform.build()

comp.build()

vitis.dispose()

